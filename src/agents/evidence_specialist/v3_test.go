package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	v3Commit = "7c486efa8223d5f66af8cf7b2ac9bb04a1ee6b91"
	v3Tree   = "e34520810b0a889a8103247d117fce0a988c37dd"
	v3Set    = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)

func v3Token() map[string]any { return contractToken("3.0") }

func v3Envelope(payload any, token string, control bool, tokens ...map[string]any) map[string]any {
	env := envelope(payload, token)
	subs := env["Submessages"].([]any)
	for _, tk := range tokens {
		subs = append(subs, tk)
	}
	env["Submessages"] = subs
	if control {
		env["MessageType"] = "control"
	}
	return env
}

// putStore writes data into the store the way core does and returns its digest.
func putStore(t *testing.T, store string, data []byte) string {
	t.Helper()
	sum := sha256.Sum256(data)
	hexd := hex.EncodeToString(sum[:])
	dir := filepath.Join(store, "sha256")
	_ = os.MkdirAll(dir, 0o755)
	if err := os.WriteFile(filepath.Join(dir, hexd), data, 0o444); err != nil {
		t.Fatal(err)
	}
	return "sha256:" + hexd
}

func v3Task(op, repo, commit string, inputs []any, mutate func(map[string]any)) map[string]any {
	now := time.Now().UTC()
	p := map[string]any{
		"kind": "task_request", "schema_version": "3.0", "task_id": "t1", "run_id": "run-1",
		"capability_version": "3.0", "issued_at": now.Format(timeLayout),
		"deadline": now.Add(30 * time.Second).Format(timeLayout),
		"context": map[string]any{"repo_id": "github.com/" + repo, "requested_revision": commit, "observed_revision": commit,
			"baseline_id": "baseline", "candidate_id": nil, "language": "go", "build_scope": buildScopeV3},
		"requirements":   []any{map[string]any{"requirement_id": "req-1", "dimension": "inventory"}},
		"operations":     []any{op},
		"inputs":         inputs,
		"budget":         map[string]any{"max_worker_jobs": 1, "max_produced_artifact_bytes": 1048576},
		"capture_set_id": v3Set,
	}
	if mutate != nil {
		mutate(p)
	}
	return p
}

func inputRef(digest, role string) map[string]any {
	return map[string]any{"digest": digest, "media_type": "application/json", "role": role}
}

type v3Fixture struct {
	srv   *httptest.Server
	store string
}

func newV3Server(t *testing.T) v3Fixture {
	srv, store := newTestServer(t, fixtureGoMod)
	return v3Fixture{srv, store}
}

func srcFileFor(t *testing.T, store, path, kind string, data []byte) map[string]any {
	digest := putStore(t, store, data)
	return map[string]any{"path": path, "kind": kind, "git_blob": gitBlobID(data), "sha256": contentSHA256(data), "bytes": len(data),
		"mode": "100644", "blob": digest, "hint": ""}
}

func sourceBundleFor(t *testing.T, store, repo, path, kind string, data []byte, mutate func(map[string]any)) (digest string, bundle map[string]any) {
	bundle = map[string]any{"schema": "opentrace.i3.source_bundle/1", "kind": "source", "repo": repo, "commit": v3Commit, "tree": v3Tree,
		"source_capture_set_id": v3Set, "listing_digest": "sha256:" + strings.Repeat("a", 64), "selected_manifest_count": 1,
		"excluded_by_policy_count": 0, "emit_scope": false, "manifest": srcFileFor(t, store, path, kind, data),
		"companions": []any{}, "siblings": []any{map[string]any{"path": path, "kind": kind}}, "extras": []any{}}
	if mutate != nil {
		mutate(bundle)
	}
	raw, _ := json.Marshal(bundle)
	return putStore(t, store, raw), bundle
}

func runInventory(t *testing.T, fx v3Fixture, bundleDigest string, mutate func(map[string]any)) map[string]any {
	t.Helper()
	task := v3Task(opRepoInventory, "modelcontextprotocol/go-sdk", v3Commit, []any{inputRef(bundleDigest, "bundle_manifest")}, mutate)
	status, msg := post(t, fx.srv, v3Envelope(task, "run-1", false, v3Token()))
	if status != 200 {
		t.Fatalf("http %d", status)
	}
	return content(t, msg)
}

// ---- gating (I3-REQ-02 item 5) ---------------------------------------------------------------

func TestV3GatingMatrix(t *testing.T) {
	fx := newV3Server(t)
	good := v3Task(opRepoInventory, "modelcontextprotocol/go-sdk", v3Commit, []any{inputRef(v3Set, "bundle_manifest")}, nil)
	rejected := func(label string, env map[string]any) {
		t.Helper()
		_, msg := post(t, fx.srv, env)
		if c := content(t, msg); c["kind"] != "rejection" || c["code"] != "unsupported_schema_version" || c["schema_version"] != "1.0" {
			t.Errorf("%s: %v", label, c)
		}
		if hasSub(msg, contractTokenSubformat) {
			t.Errorf("%s: a 1.0 rejection must not carry a contract token", label)
		}
	}
	rejected("bare 3.0 task", envelope(good, "run-1"))
	rejected("token 3.0 with a 1.0 payload", v3Envelope(taskPayload(nil), "run-1", false, v3Token()))
	rejected("token 3.0 with a 2.0 payload", v3Envelope(v2Task(nil), "run-1", false, v3Token()))
	rejected("token 2.0 with a 3.0 payload", v3Envelope(good, "run-1", false, contractToken("2.0")))
	rejected("unknown token with a 3.0 payload", v3Envelope(good, "run-1", false, contractToken("4.0")))
	capReq := map[string]any{"kind": "capability_request", "schema_version": "3.0", "request_id": "cap-3",
		"requester": map[string]any{"service_id": "a", "implementation": "python"}, "contract_versions": []any{"3.0"}}
	rejected("bare 3.0 capability request", v3Envelope(capReq, "cap-3", true))
	_, msg := post(t, fx.srv, v3Envelope(capReq, "cap-3", true, v3Token()))
	c := content(t, msg)
	ops := c["operations"].([]any)
	if c["kind"] != "capability_response" || c["schema_version"] != "3.0" || c["capability_version"] != "3.0" || len(ops) != 3 {
		t.Fatalf("3.0 capability: %v", c)
	}
	for _, want := range []string{"github_sbom_import", "osv_inventory_match", "repo_inventory"} {
		found := false
		for _, o := range ops {
			found = found || o == want
		}
		if !found {
			t.Errorf("3.0 capability lacks %s: %v", want, ops)
		}
	}
	tok := msg["Submessages"].([]any)
	echoed := false
	for _, s := range tok {
		m := s.(map[string]any)
		if m["Subformat"] == contractTokenSubformat && m["Content"] == "3.0" {
			echoed = true
		}
	}
	if !echoed {
		t.Error("the contract token must be echoed")
	}
	// the 2.0 profile is unchanged by 3.0: a 2.0 capability request still lists only I2 operations
	cap2 := map[string]any{"kind": "capability_request", "schema_version": "2.0", "request_id": "cap-2",
		"requester": map[string]any{"service_id": "a", "implementation": "python"}, "contract_versions": []any{"2.0"}}
	_, msg = post(t, fx.srv, v2Envelope(cap2, "cap-2", true, true))
	for _, o := range content(t, msg)["operations"].([]any) {
		if strings.HasPrefix(o.(string), "repo_") || strings.HasPrefix(o.(string), "osv_inventory") || strings.HasPrefix(o.(string), "github_") {
			t.Errorf("the 2.0 capability must not list the 3.0 operation %v", o)
		}
	}
}

func TestV3TaskValidationRejections(t *testing.T) {
	fx := newV3Server(t)
	data := sourceBlob(t, "modelcontextprotocol/go-sdk", v3Commit[:7], "go.mod")
	d, _ := sourceBundleFor(t, fx.store, "modelcontextprotocol/go-sdk", "go.mod", "go_mod", data, nil)
	cases := map[string]struct {
		mutate func(map[string]any)
		code   string
	}{
		"wrong capability version": {func(p map[string]any) { p["capability_version"] = "2.0" }, "unsupported_capability_version"},
		"two operations":           {func(p map[string]any) { p["operations"] = []any{opRepoInventory, "osv_inventory_match"} }, "invalid_request"},
		"unknown operation":        {func(p map[string]any) { p["operations"] = []any{"go_mod_inventory"} }, "operation_not_supported"},
		"I2 operation":             {func(p map[string]any) { p["operations"] = []any{"osv_advisory_match"} }, "operation_not_supported"},
		"build scope": {func(p map[string]any) {
			p["context"].(map[string]any)["build_scope"] = "go build ./..."
		}, "context_mismatch"},
		"expired deadline": {func(p map[string]any) {
			p["deadline"] = time.Now().UTC().Add(-time.Minute).Format(timeLayout)
		}, "deadline_exceeded"},
		"deadline too far": {func(p map[string]any) {
			p["deadline"] = time.Now().UTC().Add(time.Hour).Format(timeLayout)
		}, "invalid_request"},
		"wrong repo": {func(p map[string]any) {
			p["context"].(map[string]any)["repo_id"] = "github.com/other/repo"
		}, "context_mismatch"},
		"wrong revision": {func(p map[string]any) {
			p["context"].(map[string]any)["requested_revision"] = strings.Repeat("b", 40)
		}, "context_mismatch"},
		"observed revision differs": {func(p map[string]any) {
			p["context"].(map[string]any)["observed_revision"] = strings.Repeat("b", 40)
		}, "context_mismatch"},
		"wrong capture set": {func(p map[string]any) { p["capture_set_id"] = "sha256:" + strings.Repeat("d", 64) }, "capture_mismatch"},
	}
	for name, c := range cases {
		task := v3Task(opRepoInventory, "modelcontextprotocol/go-sdk", v3Commit, []any{inputRef(d, "bundle_manifest")}, c.mutate)
		_, msg := post(t, fx.srv, v3Envelope(task, "run-1", false, v3Token()))
		r := content(t, msg)
		if r["kind"] != "rejection" || r["code"] != c.code || r["schema_version"] != "3.0" {
			t.Errorf("%s: %v", name, r)
		}
	}
}

// ---- repo_inventory over HTTP -------------------------------------------------------------------

func TestRepoInventoryRealGoModOverHTTP(t *testing.T) {
	fx := newV3Server(t)
	data := sourceBlob(t, "modelcontextprotocol/go-sdk", v3Commit[:7], "go.mod")
	d, _ := sourceBundleFor(t, fx.store, "modelcontextprotocol/go-sdk", "go.mod", "go_mod", data, nil)
	r := runInventory(t, fx, d, nil)
	if r["status"] != "complete" || r["schema_version"] != "3.0" || r["capture_set_id"] != v3Set {
		t.Fatalf("result: %v", r)
	}
	ev := r["evidence"].([]any)
	if len(ev) != 1 {
		t.Fatalf("evidence %d", len(ev))
	}
	details := ev[0].(map[string]any)["details"].(map[string]any)
	if details["status"] != "parsed" || details["occurrence_count"].(float64) != 11 || len(details["unparsed_constructs"].([]any)) != 0 {
		t.Fatalf("details %v", details)
	}
	art := r["artifacts"].([]any)
	if len(art) != 1 || art[0].(map[string]any)["digest"] != details["table_artifact"] || details["table_artifact"] != details["table_digest"] {
		t.Fatalf("table artifact %v vs %v", art, details)
	}
	cl := r["claims"].([]any)[0].(map[string]any)
	if cl["type"] != "manifest_inventory_recorded" || cl["status"] != "supported" {
		t.Fatalf("claim %v", cl)
	}
}

func TestRepoInventoryPartialManifestIsUnknownNotSupported(t *testing.T) {
	fx := newV3Server(t)
	data := []byte("module m\nrequire (\n\texample.com/ok v1.0.0\n\texample.com/bad\x01name v1.0.0\n)\n")
	d, _ := sourceBundleFor(t, fx.store, "modelcontextprotocol/go-sdk", "go.mod", "go_mod", data, nil)
	r := runInventory(t, fx, d, nil)
	if r["status"] != "partial" {
		t.Fatalf("status %v", r["status"])
	}
	cl := r["claims"].([]any)[0].(map[string]any)
	if cl["status"] != "unknown" {
		t.Fatalf("a partial manifest must not be supported: %v", cl)
	}
	me := r["missing_evidence"].([]any)
	if len(me) == 0 || me[0].(map[string]any)["reason"] != "manifest_unsupported" {
		t.Fatalf("missing evidence %v", me)
	}
	d0 := r["evidence"].([]any)[0].(map[string]any)["details"].(map[string]any)
	if d0["status"] != "partial" || len(d0["unparsed_constructs"].([]any)) == 0 || d0["occurrence_count"].(float64) != 1 {
		t.Fatalf("details %v", d0)
	}
}

func TestRepoInventoryUnreadableKindsStayVisible(t *testing.T) {
	fx := newV3Server(t)
	for name, c := range map[string]struct {
		path, kind string
		data       []byte
		status     string
		reason     string
	}{
		"npm lockfile v1":  {"package-lock.json", "npm_lock", []byte(`{"lockfileVersion":1,"dependencies":{}}`), "unsupported", "manifest_unsupported"},
		"malformed npm":    {"package-lock.json", "npm_lock", []byte(`{"lockfileVersion":3,"packages":`), "malformed", "manifest_malformed"},
		"pnpm v8":          {"pnpm-lock.yaml", "pnpm_lock", []byte("lockfileVersion: '8.0'\n"), "unsupported", "manifest_unsupported"},
		"uv version 2":     {"uv.lock", "uv_lock", []byte("version = 2\n"), "unsupported", "manifest_unsupported"},
		"truncated uv":     {"uv.lock", "uv_lock", []byte("version = 1\n[[package]]\nname = \"a\"\ndependencies = [\n"), "partial", "manifest_unsupported"},
		"empty go.mod ok":  {"go.mod", "go_mod", []byte("module m\n"), "complete", ""},
		"package.json bad": {"package.json", "package_json", []byte(`[1,2,3]`), "malformed", "manifest_malformed"},
	} {
		d, _ := sourceBundleFor(t, fx.store, "modelcontextprotocol/go-sdk", c.path, c.kind, c.data, nil)
		r := runInventory(t, fx, d, nil)
		if r["status"] != "partial" && c.status != "complete" {
			t.Errorf("%s: status %v", name, r["status"])
		}
		if c.status == "complete" {
			if r["status"] != "complete" {
				t.Errorf("%s: %v", name, r["status"])
			}
			continue
		}
		me := r["missing_evidence"].([]any)
		if len(me) == 0 || me[0].(map[string]any)["reason"] != c.reason {
			t.Errorf("%s: missing evidence %v", name, me)
		}
		for _, cl := range r["claims"].([]any) {
			if cl.(map[string]any)["status"] == "supported" {
				t.Errorf("%s: an unreadable manifest produced a supported claim", name)
			}
		}
		if c.status == "malformed" || c.status == "unsupported" {
			st := r["evidence"].([]any)[0].(map[string]any)
			if st["kind"] != "manifest_status" || st["details"].(map[string]any)["status"] != c.status {
				t.Errorf("%s: %v", name, st)
			}
		}
	}
}

func TestRepoInventoryIntegrityAndPathChecks(t *testing.T) {
	fx := newV3Server(t)
	data := sourceBlob(t, "modelcontextprotocol/go-sdk", v3Commit[:7], "go.mod")
	// recorded git blob id differs from the bytes: the blob is not trusted
	d, _ := sourceBundleFor(t, fx.store, "modelcontextprotocol/go-sdk", "go.mod", "go_mod", data, func(b map[string]any) {
		b["manifest"].(map[string]any)["git_blob"] = strings.Repeat("0", 40)
	})
	r := runInventory(t, fx, d, nil)
	if r["status"] != "failed" || len(r["evidence"].([]any)) != 0 || len(r["claims"].([]any)) != 0 {
		t.Fatalf("git blob mismatch: %v", r["status"])
	}
	if e := r["errors"].([]any)[0].(map[string]any); e["code"] != "artifact_integrity_failure" {
		t.Fatalf("error %v", e)
	}
	// sha256 differs
	d, _ = sourceBundleFor(t, fx.store, "modelcontextprotocol/go-sdk", "go.mod", "go_mod", data, func(b map[string]any) {
		b["manifest"].(map[string]any)["sha256"] = strings.Repeat("0", 64)
	})
	if r := runInventory(t, fx, d, nil); r["status"] != "failed" {
		t.Fatalf("sha mismatch: %v", r["status"])
	}
	// blob missing from the store
	d, _ = sourceBundleFor(t, fx.store, "modelcontextprotocol/go-sdk", "go.mod", "go_mod", data, func(b map[string]any) {
		b["manifest"].(map[string]any)["blob"] = "sha256:" + strings.Repeat("e", 64)
	})
	r = runInventory(t, fx, d, nil)
	if r["status"] != "failed" || r["errors"].([]any)[0].(map[string]any)["code"] != "artifact_not_found" {
		t.Fatalf("missing blob: %v", r)
	}
	// hostile paths and kinds are re-checked by B and rejected
	for name, mut := range map[string]func(map[string]any){
		"dotdot":        func(b map[string]any) { b["manifest"].(map[string]any)["path"] = "../go.mod" },
		"absolute":      func(b map[string]any) { b["manifest"].(map[string]any)["path"] = "/etc/go.mod" },
		"control":       func(b map[string]any) { b["manifest"].(map[string]any)["path"] = "a\nb/go.mod" },
		"backslash":     func(b map[string]any) { b["manifest"].(map[string]any)["path"] = "a\\go.mod" },
		"excluded":      func(b map[string]any) { b["manifest"].(map[string]any)["path"] = "vendor/x/go.mod" },
		"kind mismatch": func(b map[string]any) { b["manifest"].(map[string]any)["kind"] = "npm_lock" },
		"not inventory": func(b map[string]any) {
			b["manifest"].(map[string]any)["path"] = "go.sum"
			b["manifest"].(map[string]any)["kind"] = "go_sum"
		},
		"too long": func(b map[string]any) { b["manifest"].(map[string]any)["path"] = strings.Repeat("d/", 300) + "go.mod" },
	} {
		d, _ = sourceBundleFor(t, fx.store, "modelcontextprotocol/go-sdk", "go.mod", "go_mod", data, mut)
		task := v3Task(opRepoInventory, "modelcontextprotocol/go-sdk", v3Commit, []any{inputRef(d, "bundle_manifest")}, nil)
		_, msg := post(t, fx.srv, v3Envelope(task, "run-1", false, v3Token()))
		if c := content(t, msg); c["kind"] != "rejection" || c["code"] != "invalid_request" {
			t.Errorf("%s: %v", name, c)
		}
	}
	// a bundle that is not a source bundle fails closed
	notBundle := putStore(t, fx.store, []byte(`{"kind":"osv"}`))
	if r := runInventory(t, fx, notBundle, nil); r["status"] != "failed" {
		t.Fatalf("not a bundle: %v", r["status"])
	}
}

func TestRepoInventoryScopeAndStatuses(t *testing.T) {
	fx := newV3Server(t)
	lock := []byte("lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      a:\n        specifier: ^1\n        version: 1.0.0\n  packages/core:\n    dependencies:\n      b:\n        specifier: ^1\n        version: 1.0.0\npackages:\n  a@1.0.0:\n    resolution: {integrity: sha512-x}\n  b@1.0.0:\n    resolution: {integrity: sha512-y}\n")
	file := func(p, kind, hint string) map[string]any {
		return map[string]any{"path": p, "kind": kind, "git_blob": strings.Repeat("1", 40), "sha256": strings.Repeat("2", 64), "bytes": 3, "mode": "100644", "blob": "", "hint": hint}
	}
	d, _ := sourceBundleFor(t, fx.store, "modelcontextprotocol/typescript-sdk", "pnpm-lock.yaml", "pnpm_lock", lock, func(b map[string]any) {
		b["emit_scope"] = true
		b["selected_manifest_count"] = 9
		b["excluded_by_policy_count"] = 1
		b["siblings"] = []any{map[string]any{"path": "pnpm-lock.yaml", "kind": "pnpm_lock"}, map[string]any{"path": "package.json", "kind": "package_json"},
			map[string]any{"path": "packages/core/package.json", "kind": "package_json"}, map[string]any{"path": "packages/orphan/package.json", "kind": "package_json"},
			map[string]any{"path": "pnpm-workspace.yaml", "kind": "pnpm_workspace"}}
		b["extras"] = []any{file("pnpm-workspace.yaml", "pnpm_workspace", ""), file("yarn.lock", "yarn_lock", ""), file("docs/requirements.txt", "requirements_txt", ""),
			file("node_modules/x/package.json", "package_json", "excluded_path_segment"), file("link/go.mod", "go_mod", "mode_120000"),
			file("big/package-lock.json", "npm_lock", "too_large"), file("a\nb/go.mod", "go_mod", "rejected_control_character"),
			file("sub/pyproject.toml", "pyproject", "")}
	})
	task := v3Task(opRepoInventory, "modelcontextprotocol/typescript-sdk", v3Commit, []any{inputRef(d, "bundle_manifest")}, func(p map[string]any) {
		p["context"].(map[string]any)["repo_id"] = "github.com/modelcontextprotocol/typescript-sdk"
	})
	_, msg := post(t, fx.srv, v3Envelope(task, "run-1", false, v3Token()))
	r := content(t, msg)
	statuses := map[string]map[string]any{}
	kinds := map[string]int{}
	for _, e := range r["evidence"].([]any) {
		ev := e.(map[string]any)
		kinds[ev["kind"].(string)]++
		if ev["kind"] == "manifest_status" {
			det := ev["details"].(map[string]any)
			statuses[det["path"].(string)] = det
		}
	}
	if kinds["repo_source_scope"] != 1 || kinds["manifest_inventory"] != 1 {
		t.Fatalf("kinds %v", kinds)
	}
	want := map[string][2]string{
		"package.json":                {"covered_by_lock", "pnpm-lock.yaml"},
		"packages/core/package.json":  {"covered_by_lock", "pnpm-lock.yaml"},
		"pnpm-workspace.yaml":         {"recognized_not_inventoried", "pnpm-lock.yaml"},
		"yarn.lock":                   {"unsupported", ""},
		"docs/requirements.txt":       {"unsupported", ""},
		"node_modules/x/package.json": {"excluded_by_policy", ""},
		"link/go.mod":                 {"unsupported", ""},
		"big/package-lock.json":       {"too_large", ""},
		"sub/pyproject.toml":          {"lock_absent", ""},
	}
	for p, w := range want {
		st := statuses[p]
		if st == nil || st["status"] != w[0] {
			t.Errorf("%s: %v want %v", p, st, w)
			continue
		}
		if w[1] != "" && st["covered_by"] != w[1] {
			t.Errorf("%s: covered_by %v", p, st["covered_by"])
		}
	}
	if _, ok := statuses["packages/orphan/package.json"]; ok {
		t.Error("a package.json that the lock does not list must not be reported as covered")
	}
	for p, st := range statuses {
		if strings.ContainsAny(p, "\n\x00") {
			t.Errorf("a hostile path leaked into evidence: %q %v", p, st)
		}
	}
	hashed := false
	for p := range statuses {
		hashed = hashed || strings.HasPrefix(p, "rejected-path-")
	}
	if !hashed {
		t.Errorf("the rejected path must be reported under a hash label: %v", statuses)
	}
}

func TestRepoInventoryGoSumCompanionAndLocklessPackageJSON(t *testing.T) {
	fx := newV3Server(t)
	gomod := []byte("module m\nrequire example.com/a v1.0.0\nrequire example.com/b v1.0.0\n")
	gosum := []byte("example.com/a v1.0.0 h1:abc=\nexample.com/a v1.0.0/go.mod h1:def=\n")
	d, _ := sourceBundleFor(t, fx.store, "modelcontextprotocol/go-sdk", "go.mod", "go_mod", gomod, func(b map[string]any) {
		b["companions"] = []any{srcFileFor(t, fx.store, "go.sum", "go_sum", gosum)}
	})
	r := runInventory(t, fx, d, nil)
	var sum map[string]any
	for _, e := range r["evidence"].([]any) {
		if ev := e.(map[string]any); ev["kind"] == "manifest_status" {
			sum = ev["details"].(map[string]any)
		}
	}
	if sum == nil || sum["path"] != "go.sum" || sum["status"] != "recognized_not_inventoried" || sum["covered_by"] != "go.mod" {
		t.Fatalf("go.sum companion: %v", sum)
	}
	// the table records integrity for a only
	tbl := r["artifacts"].([]any)[0].(map[string]any)
	raw, _ := base64.StdEncoding.DecodeString(tbl["content_b64"].(string))
	if !strings.Contains(string(raw), `"integrity_recorded":true`) || !strings.Contains(string(raw), `"integrity_recorded":false`) {
		t.Fatalf("integrity flags missing: %s", raw)
	}
	pj := []byte(`{"name":"x","dependencies":{"left-pad":"latest"},"devDependencies":{"vite":"^5"}}`)
	d, _ = sourceBundleFor(t, fx.store, "modelcontextprotocol/go-sdk", "www/package.json", "package_json", pj, nil)
	r = runInventory(t, fx, d, nil)
	if r["status"] != "partial" {
		t.Fatalf("lockless package.json: %v", r["status"])
	}
	me := r["missing_evidence"].([]any)
	if len(me) != 1 || me[0].(map[string]any)["reason"] != "lock_absent" {
		t.Fatalf("missing evidence %v", me)
	}
	if cl := r["claims"].([]any)[0].(map[string]any); cl["status"] != "supported" {
		// the declared specifiers were fully read; the gap is the absent lock, carried as missing evidence
		t.Fatalf("claim %v", cl)
	}
}

func TestRunV3RecoversFromAHandlerPanic(t *testing.T) {
	srv := NewServer(t.TempDir(), nil)
	mx, bytesMax := 1, 1<<20
	task := &TaskRequest{TaskID: "t1", RunID: "run-1", Context: Context{RepoID: "r", RequestedRevision: "x", BuildScope: buildScopeV3},
		Requirements: []Requirement{{RequirementID: "req-1", Dimension: "inventory"}}, Budget: &Budget{MaxWorkerJobs: &mx, MaxProducedArtifactBytes: &bytesMax}}
	msg := srv.runV3(func(*Server, context.Context, *TaskRequest, time.Time, []Part) *Message { panic("boom") },
		context.Background(), task, time.Now().Add(time.Minute), nil, opRepoInventory)
	var res Result
	if err := json.Unmarshal(msg.Content, &res); err != nil {
		t.Fatal(err)
	}
	if res.Status != "failed" || len(res.Evidence) != 0 || len(res.Claims) != 0 || len(res.Errors) != 1 || res.Errors[0].Code != "worker_failed" {
		t.Fatalf("a panic must become a failed result with no evidence: %+v", res)
	}
}
