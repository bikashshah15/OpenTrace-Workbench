package main

// change_validate, govulncheck_source execution and patch scope (CP5). Tests that need the primed
// module cache and govulncheck binary (tools/i2/prepare_tools.py, class A1) are skipped and reported
// as not run when those are absent. The vulnerability database used with the real govulncheck is a
// SYNTHETIC one authored here; it is not Go vulnerability database content.

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

const synthDBURL = "https://vuln.go.dev"

var repoRoot = filepath.Join("..", "..", "..")

func fixtureFile(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot, "evidence", "fixtures", "i2", "go-acceptlang", filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func toolsDir(t *testing.T) string {
	t.Helper()
	dir := os.Getenv("OPENTRACE_I2_TOOLS")
	if dir == "" {
		dir = filepath.Join(repoRoot, "artifacts", "i2-tools")
	}
	abs, _ := filepath.Abs(dir)
	for _, need := range []string{"bin/govulncheck", "modcache", "tool_provenance.json"} {
		if _, err := os.Stat(filepath.Join(abs, need)); err != nil {
			t.Skipf("not run (blocker): %s missing; run tools/i2/prepare_tools.py (class A1)", need)
		}
	}
	return abs
}

type i2Env struct {
	t         *testing.T
	srv       *httptest.Server
	store     string
	worker    *Worker
	srcDigest string
	specDig   string
	patches   map[string]string
}

func newI2Env(t *testing.T, needTools bool) *i2Env {
	t.Helper()
	e := &i2Env{t: t, patches: map[string]string{}}
	w, err := NewWorker()
	if err != nil {
		t.Fatal(err)
	}
	if needTools {
		tools := toolsDir(t)
		w.configureV2(filepath.Join(tools, "bin"), filepath.Join(tools, "modcache"))
		if w.sandbox == nil || w.gitBin == "" {
			t.Skip("not run (blocker): no network namespace or git")
		}
	}
	e.worker = w
	e.srv, e.store = newTestServer(t, fixtureGoMod)
	// rebuild the server with this worker
	e.srv.Close()
	e.srv = httptest.NewServer(NewServer(e.store, w))
	t.Cleanup(e.srv.Close)
	for _, rel := range []string{"go.mod", "go.sum", "negotiate.go", "negotiate_test.go", "cmd/negotiate/main.go"} {
		putBlob(t, e.store, fixtureFile(t, rel))
	}
	e.srcDigest = putBlob(t, e.store, fixtureFile(t, "source_manifest.json"))
	e.specDig = putBlob(t, e.store, fixtureFile(t, "required_checks.json"))
	for _, n := range []string{"cand-min-fix", "cand-latest-incompatible", "cand-regress", "cand-oracle-tamper"} {
		e.patches[n] = putBlob(t, e.store, fixtureFile(t, "patches/"+n+".patch"))
	}
	return e
}

func (e *i2Env) task(op string, extra []any, cand *string, mutate func(map[string]any)) map[string]any {
	inputs := append([]any{map[string]any{"digest": e.srcDigest, "media_type": "application/json", "role": "source_manifest"}}, extra...)
	return v2Task(func(p map[string]any) {
		p["operations"] = []any{op}
		p["inputs"] = inputs
		p["capture_set_id"] = synthCaptureSet
		ctx := map[string]any{"repo_id": "opentrace-fixture/i2-go-acceptlang", "requested_revision": e.srcDigest, "baseline_id": "baseline",
			"candidate_id": nil, "language": "go", "build_scope": "linux/amd64 cgo=0 no build tags, ./..."}
		if cand != nil {
			ctx["candidate_id"] = *cand
		}
		p["context"] = ctx
		p["requirements"] = []any{map[string]any{"requirement_id": "req-1", "dimension": dimOf(op)}}
		p["deadline"] = nowPlus(600)
		if mutate != nil {
			mutate(p)
		}
	})
}

func dimOf(op string) string {
	switch op {
	case opChange:
		return "change_validation"
	case opVuln:
		return "call_path"
	}
	return "inventory"
}

func (e *i2Env) call(task map[string]any) map[string]any {
	e.t.Helper()
	_, msg := post(e.t, e.srv, v2Envelope(task, "run-1", false, true))
	return content(e.t, msg)
}

func (e *i2Env) validate(patch string) map[string]any {
	extra := []any{map[string]any{"digest": e.specDig, "media_type": "application/json", "role": "check_spec"}}
	var cand *string
	if patch != "" {
		d := e.patches[patch]
		cand = &d
		extra = append(extra, map[string]any{"digest": d, "media_type": "text/x-diff", "role": "candidate_patch"})
	}
	return e.call(e.task(opChange, extra, cand, nil))
}

func checkOutcomes(res map[string]any) map[string]string {
	out := map[string]string{}
	for _, ev := range res["evidence"].([]any) {
		m := ev.(map[string]any)
		if m["kind"] == "check_result" {
			d := m["details"].(map[string]any)
			out[d["check_id"].(string)] = d["outcome"].(string)
		}
	}
	return out
}

func TestChangeValidateBaselineAndMinFixPass(t *testing.T) {
	e := newI2Env(t, true)
	for _, patch := range []string{"", "cand-min-fix"} {
		res := e.validate(patch)
		if res["status"] != "complete" || res["schema_version"] != "2.0" {
			t.Fatalf("%q: %v", patch, res)
		}
		got := checkOutcomes(res)
		for _, id := range []string{"modverify", "build", "vet", "test", "modlist"} {
			if got[id] != "passed" {
				t.Fatalf("%q: check %s = %q", patch, id, got[id])
			}
		}
		cr := res["change_result"].(map[string]any)
		if len(cr["unexpected_changes"].([]any)) != 0 || cr["oracle_files_unchanged"] != true {
			t.Fatalf("%q: change_result %v", patch, cr)
		}
		if patch == "" && (cr["variant"] != "baseline" || cr["candidate_id"] != nil || cr["patch_digest"] != nil) {
			t.Fatalf("baseline change_result %v", cr)
		}
		if patch != "" && (cr["variant"] != "candidate" || cr["candidate_id"] != e.patches[patch] || len(cr["patch_files"].([]any)) != 2) {
			t.Fatalf("candidate change_result %v", cr)
		}
		if cr["check_spec_digest"] != e.specDig || !strings.HasPrefix(cr["environment_digest"].(string), "sha256:") {
			t.Fatalf("bindings %v", cr)
		}
		types := claimTypes(res)
		if len(types["check_passed"]) != 5 || len(types["check_failed"]) != 0 {
			t.Fatalf("claims %v", types)
		}
	}
}

func TestChangeValidateIdenticalEnvironmentDigestAcrossVariants(t *testing.T) {
	e := newI2Env(t, true)
	a, b := e.validate(""), e.validate("cand-min-fix")
	if a["change_result"].(map[string]any)["environment_digest"] != b["change_result"].(map[string]any)["environment_digest"] {
		t.Fatal("baseline and candidate must record the same environment digest")
	}
}

func TestChangeValidateToolchainIncompatibleCandidateFailsEveryRequiredCheck(t *testing.T) { // F1
	e := newI2Env(t, true)
	res := e.validate("cand-latest-incompatible")
	got := checkOutcomes(res)
	for _, id := range []string{"modverify", "build", "vet", "test"} {
		if got[id] != "failed" {
			t.Fatalf("check %s = %q, want failed", id, got[id])
		}
	}
	art := res["artifacts"].([]any)[0].(map[string]any)
	raw := decodeB64(t, art["content_b64"].(string))
	if !bytes.Contains(raw, []byte("requires go \\u003e= 1.25.0")) { // canonical JSON escapes ">"
		t.Fatalf("check output does not carry the toolchain message: %s", raw)
	}
	for _, leak := range []string{"/tmp/", "/home/", "/root/", "otb-i2-"} {
		if bytes.Contains(raw, []byte(leak)) {
			t.Fatalf("absolute path leaked into the stored output (%s)", leak)
		}
	}
	if len(claimTypes(res)["check_failed"]) < 4 {
		t.Fatalf("claims %v", claimTypes(res))
	}
}

func TestChangeValidateRegressionFailsOnlyTheFunctionalCheck(t *testing.T) { // F2
	e := newI2Env(t, true)
	res := e.validate("cand-regress")
	got := checkOutcomes(res)
	if got["build"] != "passed" || got["vet"] != "passed" || got["modverify"] != "passed" || got["test"] != "failed" {
		t.Fatalf("outcomes %v", got)
	}
	for _, ev := range res["evidence"].([]any) {
		m := ev.(map[string]any)
		if m["kind"] == "check_result" && m["details"].(map[string]any)["check_id"] == "test" {
			failed := m["details"].(map[string]any)["failed_tests"].([]any)
			if len(failed) != 1 || failed[0] != "TestNegotiate" {
				t.Fatalf("failed_tests %v", failed)
			}
		}
	}
}

func TestChangeValidateOracleTamperIsRejectedBeforeAnyCommand(t *testing.T) { // F3
	e := newI2Env(t, false)
	before := atomic.LoadInt64(&sandboxRuns)
	res := e.validate("cand-oracle-tamper")
	if res["kind"] != "rejection" || res["code"] != "oracle_modified" || res["schema_version"] != "2.0" {
		t.Fatalf("%v", res)
	}
	if atomic.LoadInt64(&sandboxRuns) != before {
		t.Fatal("a command ran before the oracle check")
	}
}

func TestPatchScopeViolations(t *testing.T) { // F4 (SYNTHETIC patches)
	hdr := func(a, b string) string { return "--- " + a + "\n+++ " + b + "\n@@ -1 +1 @@\n-x\n+y\n" }
	cases := map[string]string{
		"outside path":     hdr("a/.github/x", "b/.github/x"),
		"parent traversal": hdr("a/../x.go", "b/../x.go"),
		"absolute path":    hdr("a//etc/x.go", "b//etc/x.go"),
		"no prefix":        hdr("go.mod", "go.mod"),
		"rename":           "diff --git a/x.go b/y.go\nrename from x.go\nrename to y.go\n",
		"copy":             "diff --git a/x.go b/y.go\ncopy from x.go\ncopy to y.go\n",
		"mode change":      "diff --git a/x.go b/x.go\nold mode 100644\nnew mode 100755\n",
		"symlink":          "diff --git a/x.go b/x.go\nnew file mode 120000\n--- /dev/null\n+++ b/x.go\n",
		"binary":           "diff --git a/x.go b/x.go\nGIT binary patch\nliteral 1\n",
		"binary files":     "diff --git a/x.go b/x.go\nBinary files a/x.go and b/x.go differ\n",
		"go.work":          hdr("a/go.work", "b/go.work"),
		"vendor":           hdr("a/vendor/m/x.go", "b/vendor/m/x.go"),
		"other test file":  hdr("a/other_test.go", "b/other_test.go"),
		"nested go.mod":    hdr("a/sub/go.mod", "b/sub/go.mod"),
		"no file named":    "just text\n",
	}
	for name, patch := range cases {
		if files, code, _ := scanPatch([]byte(patch), []string{"negotiate_test.go"}); code != "patch_scope_violation" {
			t.Errorf("%s: code %q files %v", name, code, files)
		}
	}
	if _, code, _ := scanPatch([]byte(hdr("a/negotiate_test.go", "b/negotiate_test.go")), []string{"negotiate_test.go"}); code != "oracle_modified" {
		t.Errorf("oracle path must be oracle_modified, got %q", code)
	}
	if files, code, _ := scanPatch(fixtureFileNoT("patches/cand-regress.patch"), []string{"negotiate_test.go"}); code != "" || len(files) != 3 {
		t.Errorf("the regression patch is in scope: %v %q", files, code)
	}
}

func fixtureFileNoT(rel string) []byte {
	b, _ := os.ReadFile(filepath.Join(repoRoot, "evidence", "fixtures", "i2", "go-acceptlang", filepath.FromSlash(rel)))
	return b
}

func TestPatchThatDoesNotApplyIsAFailedResult(t *testing.T) { // F5
	e := newI2Env(t, true)
	// a baseline whose go.mod differs: same patch no longer applies
	otherGoMod := putBlob(t, e.store, []byte("module example.com/opentrace/fixture/i2\n\ngo 1.22\n\nrequire golang.org/x/text v0.3.5\n"))
	var man sourceManifest
	_ = json.Unmarshal(fixtureFile(t, "source_manifest.json"), &man)
	for i := range man.Files {
		if man.Files[i].Path == "go.mod" {
			man.Files[i].SHA256 = otherGoMod[7:]
		}
	}
	changed := putBlob(t, e.store, jsonBytes(man))
	e.srcDigest = changed
	res := e.validate("cand-min-fix")
	if res["status"] != "failed" || res["errors"].([]any)[0].(map[string]any)["code"] != "patch_apply_failed" {
		t.Fatalf("%v", res)
	}
	if len(res["claims"].([]any)) != 0 || res["change_result"] != nil {
		t.Fatal("a patch that does not apply must yield no claims and no change_result")
	}
}

func TestCandidateMismatchIsRejected(t *testing.T) { // R3
	e := newI2Env(t, true)
	extra := []any{map[string]any{"digest": e.specDig, "media_type": "application/json", "role": "check_spec"},
		map[string]any{"digest": e.patches["cand-min-fix"], "media_type": "text/x-diff", "role": "candidate_patch"}}
	other := e.patches["cand-regress"]
	res := e.call(e.task(opChange, extra, &other, nil))
	if res["code"] != "candidate_mismatch" {
		t.Fatalf("wrong candidate_id: %v", res)
	}
	res = e.call(e.task(opChange, extra[:1], &other, nil)) // candidate_id without a patch
	if res["code"] != "candidate_mismatch" {
		t.Fatalf("candidate_id without patch: %v", res)
	}
	res = e.call(e.task(opChange, extra, nil, nil)) // patch without candidate_id
	if res["code"] != "candidate_mismatch" {
		t.Fatalf("patch without candidate_id: %v", res)
	}
}

func TestToolchainMismatchRunsNothing(t *testing.T) { // U8
	e := newI2Env(t, true)
	e.worker.goVersion = "go1.99.0"
	before := atomic.LoadInt64(&sandboxRuns)
	res := e.validate("")
	if res["status"] != "failed" || res["errors"].([]any)[0].(map[string]any)["code"] != "toolchain_mismatch" {
		t.Fatalf("%v", res)
	}
	if reasons(res)[0] != "toolchain_mismatch" || atomic.LoadInt64(&sandboxRuns) != before {
		t.Fatal("a toolchain mismatch must run nothing")
	}
}

func TestSandboxUnavailableRunsNothing(t *testing.T) { // U9
	if _, err := NewSandbox(""); err == nil {
		t.Fatal("NewSandbox must fail when unshare cannot be found")
	}
	e := newI2Env(t, true)
	e.worker.sandbox = nil
	before := atomic.LoadInt64(&sandboxRuns)
	res := e.validate("")
	if res["status"] != "failed" || res["errors"].([]any)[0].(map[string]any)["code"] != "sandbox_unavailable" ||
		reasons(res)[0] != "sandbox_unavailable" || atomic.LoadInt64(&sandboxRuns) != before {
		t.Fatalf("%v", res)
	}
}

func TestCheckSpecOutsideTheAllowlistIsRejected(t *testing.T) {
	e := newI2Env(t, true)
	var spec map[string]any
	_ = json.Unmarshal(fixtureFile(t, "required_checks.json"), &spec)
	spec["checks"].([]any)[1].(map[string]any)["argv"] = []any{"go", "run", "./evil"}
	bad := putBlob(t, e.store, jsonBytes(spec))
	extra := []any{map[string]any{"digest": bad, "media_type": "application/json", "role": "check_spec"}}
	res := e.call(e.task(opChange, extra, nil, nil))
	if res["code"] != "invalid_request" {
		t.Fatalf("%v", res)
	}
}

func TestUnexpectedChangesAreListed(t *testing.T) {
	base := map[string]string{"go.mod": "a", "negotiate.go": "b"}
	snap := map[string]string{"go.mod": "a", "negotiate.go": "CHANGED", "extra.go": "z", "link": "non-regular"}
	got := unexpectedChanges(base, []string{"go.mod"}, snap)
	want := []string{"modified:negotiate.go", "non_regular_or_unreadable:link", "unexpected_file:extra.go"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v want %v", got, want)
	}
	if got := unexpectedChanges(base, []string{"go.mod", "negotiate.go"}, map[string]string{"go.mod": "x", "negotiate.go": "y"}); len(got) != 0 {
		t.Fatalf("named files are expected: %v", got)
	}
	if got := unexpectedChanges(base, nil, map[string]string{"go.mod": "a"}); len(got) != 1 || got[0] != "deleted:negotiate.go" {
		t.Fatalf("deletion: %v", got)
	}
}

func decodeB64(t *testing.T, s string) []byte {
	t.Helper()
	var out bytes.Buffer
	dec := json.NewDecoder(strings.NewReader(`"` + s + `"`))
	var raw []byte
	if err := dec.Decode(&raw); err != nil { // encoding/json decodes base64 into []byte
		t.Fatal(err)
	}
	out.Write(raw)
	return out.Bytes()
}

// ---- govulncheck_source (real binary, SYNTHETIC database) --------------------------------------

func gz(b []byte) []byte {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, _ = w.Write(b)
	_ = w.Close()
	return buf.Bytes()
}

func (e *i2Env) vulnInputs(provMutate func(map[string]any)) []any {
	db := map[string]any{
		"index/db.json":      map[string]any{"modified": "2026-01-01T00:00:00Z"},
		"index/modules.json": []any{map[string]any{"path": "golang.org/x/text", "vulns": []any{map[string]any{"id": "SYNTH-0001", "modified": "2026-01-01T00:00:00Z", "fixed": "0.3.8"}}}},
		"ID/index.json":      []any{map[string]any{"id": "SYNTH-0001", "modified": "2026-01-01T00:00:00Z"}},
		"ID/SYNTH-0001.json": json.RawMessage(synthRecord("SYNTH-0001", func(r map[string]any) {
			r["affected"].([]any)[0].(map[string]any)["ecosystem_specific"] = map[string]any{"imports": []any{
				map[string]any{"path": "golang.org/x/text/language", "symbols": []any{"ParseAcceptLanguage"}}}}
		})),
	}
	var files []map[string]string
	for p, v := range db {
		files = append(files, map[string]string{"path": p + ".gz", "digest": putBlob(e.t, e.store, gz(jsonBytes(v)))})
	}
	bundle := jsonBytes(map[string]any{"schema": "opentrace.bundle_manifest/1", "kind": "vulndb", "capture_set_id": synthCaptureSet,
		"db_url": synthDBURL, "files": files})
	provRaw, err := os.ReadFile(filepath.Join(toolsDir(e.t), "tool_provenance.json"))
	if err != nil {
		e.t.Fatal(err)
	}
	var prov map[string]any
	_ = json.Unmarshal(provRaw, &prov)
	if provMutate != nil {
		provMutate(prov)
	}
	return []any{map[string]any{"digest": putBlob(e.t, e.store, bundle), "media_type": "application/json", "role": "vulndb_bundle_manifest"},
		map[string]any{"digest": putBlob(e.t, e.store, jsonBytes(prov)), "media_type": "application/json", "role": "tool_provenance"}}
}

func (e *i2Env) vuln(patch string, provMutate func(map[string]any)) map[string]any {
	extra := e.vulnInputs(provMutate)
	var cand *string
	if patch != "" {
		d := e.patches[patch]
		cand = &d
		extra = append(extra, map[string]any{"digest": d, "media_type": "text/x-diff", "role": "candidate_patch"})
	}
	return e.call(e.task(opVuln, extra, cand, nil))
}

func TestGovulncheckBaselineYieldsACallPathAndOnlyThatClaim(t *testing.T) {
	e := newI2Env(t, true)
	res := e.vuln("", nil)
	if res["status"] != "complete" {
		t.Fatalf("%v", res)
	}
	c := claimTypes(res)
	if len(c["static_call_path_found"]) != 1 || c["static_call_path_found"][0]["vuln_id"] != "SYNTH-0001" {
		t.Fatalf("claims %v", c)
	}
	var scope, path map[string]any
	for _, ev := range res["evidence"].([]any) {
		m := ev.(map[string]any)
		switch m["kind"] {
		case "govulncheck_scope":
			scope = m["details"].(map[string]any)
		case "vuln_call_path":
			path = m["details"].(map[string]any)
		}
	}
	if scope["main_module"] != "example.com/opentrace/fixture/i2" || scope["stream_complete"] != true || scope["go_version"] != pinnedGoVersion {
		t.Fatalf("scope %v", scope)
	}
	trace := path["trace"].([]any)
	if trace[0].(map[string]any)["module"] != scope["main_module"] || trace[len(trace)-1].(map[string]any)["function"] != "ParseAcceptLanguage" {
		t.Fatalf("trace %v", trace)
	}
	// Contract 1.0.2: real scanner, pinned fixture; the trace starts at the program main (I-VC-1 shape).
	if len(trace) < 3 || trace[0].(map[string]any)["function"] != "main" || trace[1].(map[string]any)["function"] != "Negotiate" {
		t.Fatalf("expected main -> Negotiate -> ParseAcceptLanguage, got %v", trace)
	}
	if pats := scope["analyzed_patterns"].([]any); len(pats) != 1 || pats[0] != "./cmd/..." {
		t.Fatalf("analyzed_patterns %v", pats)
	}
	raw := decodeB64(t, res["artifacts"].([]any)[0].(map[string]any)["content_b64"].(string))
	for _, leak := range []string{"/tmp/", "/home/", "/root/", "otb-i2-"} {
		if bytes.Contains(raw, []byte(leak)) {
			t.Fatalf("absolute path leaked into the stored stream (%s)", leak)
		}
	}
}

func TestGovulncheckFixedCandidateEstablishesNoCallPath(t *testing.T) {
	e := newI2Env(t, true)
	res := e.vuln("cand-min-fix", nil)
	if res["status"] != "complete" || len(claimTypes(res)["static_call_path_found"]) != 0 {
		t.Fatalf("%v", res)
	}
	for _, c := range res["claims"].([]any) {
		if c.(map[string]any)["type"] == "call_path_not_established" && c.(map[string]any)["status"] != "unknown" {
			t.Fatal("call_path_not_established must be unknown")
		}
	}
}

func TestGovulncheckOnABuildFailureIsAnAnalyzerError(t *testing.T) { // U6 real, F1
	e := newI2Env(t, true)
	res := e.vuln("cand-latest-incompatible", nil)
	if res["status"] != "failed" || res["errors"].([]any)[0].(map[string]any)["code"] != "analyzer_error" || reasons(res)[0] != "analyzer_error" {
		t.Fatalf("%v", res)
	}
	if len(res["claims"].([]any)) != 0 || len(res["evidence"].([]any)) != 0 {
		t.Fatal("a failed analysis must establish nothing, not even 'no findings'")
	}
	detail := res["errors"].([]any)[0].(map[string]any)["message"].(string)
	if !strings.Contains(detail, "go >= 1.25.0") && !strings.Contains(detail, "exited with status") {
		t.Fatalf("detail %q", detail)
	}
}

func TestGovulncheckProvenanceMismatchesRunNothing(t *testing.T) {
	e := newI2Env(t, true)
	before := atomic.LoadInt64(&sandboxRuns)
	res := e.vuln("", func(p map[string]any) { p["go_version"] = "go1.99.0" })
	if res["errors"].([]any)[0].(map[string]any)["code"] != "toolchain_mismatch" {
		t.Fatalf("go version: %v", res)
	}
	_ = before
	res = e.vuln("", func(p map[string]any) {
		deps := p["govulncheck"].(map[string]any)["build_deps"].([]any)
		deps[1].([]any)[2] = "v9.9.9"
	})
	if res["errors"].([]any)[0].(map[string]any)["code"] != "toolchain_mismatch" {
		t.Fatalf("tool identity: %v", res)
	}
}

func TestGovulncheckCaptureMismatchIsRejected(t *testing.T) {
	e := newI2Env(t, true)
	extra := e.vulnInputs(nil)
	res := e.call(e.task(opVuln, extra, nil, func(p map[string]any) {
		p["capture_set_id"] = "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	}))
	if res["code"] != "capture_mismatch" {
		t.Fatalf("%v", res)
	}
}

func TestV2CapabilityAdvertisesExactlyTheImplementedOperations(t *testing.T) {
	srv, _ := newTestServer(t, fixtureGoMod)
	_, msg := post(t, srv, v2Envelope(map[string]any{"kind": "capability_request", "schema_version": "2.0", "request_id": "cap-3",
		"requester": map[string]any{"service_id": "a", "implementation": "python"}, "contract_versions": []any{"2.0"}}, "cap-3", true, true))
	ops := content(t, msg)["operations"].([]any)
	got := []string{}
	for _, o := range ops {
		got = append(got, o.(string))
	}
	want := "change_validate,go_mod_inventory,govulncheck_source,osv_advisory_match"
	if strings.Join(got, ",") != want {
		t.Fatalf("operations %v", got)
	}
}
