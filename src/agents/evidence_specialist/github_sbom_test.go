package main

// SYNTHETIC hosted-exchange captures (state machine, parser and binding behavior only). Nothing here is
// a GitHub response; the documents are authored in this file from the shapes in the official
// documentation and support no claim about any real repository.

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

type synthHosted struct {
	t   *testing.T
	fx  v3Fixture
	b   hostedBundle
	seq int
}

const hostedRepo = "modelcontextprotocol/go-sdk"

func newSynthHosted(t *testing.T) *synthHosted {
	return &synthHosted{t: t, fx: newV3Server(t), b: hostedBundle{Schema: "opentrace.i3.hosted_bundle/1", Kind: "hosted", CaptureSetID: v3Set,
		Repo: hostedRepo, RequestedPin: v3Commit, CredentialClass: "unauthenticated"}}
}

func ip(n int) *int { return &n }

func (h *synthHosted) entry(kind string, status *int, headers map[string]string, body any, hops []map[string]any) {
	h.seq++
	e := hostedEntry{Seq: h.seq, Kind: kind, Method: "GET", URL: "https://api.github.com/x", Status: status, Headers: headers, Hops: hops}
	if body != nil {
		var raw []byte
		switch v := body.(type) {
		case []byte:
			raw = v
		default:
			raw, _ = json.Marshal(v)
		}
		e.Response, e.Bytes = putStore(h.t, h.fx.store, raw), len(raw)
	}
	h.b.Entries = append(h.b.Entries, e)
}

func fetchURL(repo string) string {
	return "https://api.github.com/repos/" + repo + "/dependency-graph/sbom/fetch-report/3fa85f64-5717-4562-b3fc-2c963f66afa6"
}

func (h *synthHosted) head(sha string) {
	h.entry("github_branch_head", ip(200), nil, map[string]any{"commit": map[string]any{"sha": sha}}, nil)
}

// happy: head, generate 201, pending x n, 302, download 200.
func (h *synthHosted) happy(doc any, polls int) { h.happyAfter(doc, polls, strings.Repeat("a", 40)) }

func (h *synthHosted) happyAfter(doc any, polls int, after string) {
	h.entry("github_repo_metadata", ip(200), nil, map[string]any{"id": 1, "default_branch": "main", "archived": false, "fork": false,
		"license": map[string]any{"spdx_id": "Apache-2.0"}}, nil)
	h.head(strings.Repeat("a", 40))
	h.entry("github_sbom_generate", ip(201), nil, map[string]any{"sbom_url": fetchURL(hostedRepo)}, nil)
	for i := 0; i < polls; i++ {
		h.entry("github_sbom_poll", ip(202), nil, nil, nil)
	}
	h.entry("github_sbom_poll", ip(302), nil, nil, []map[string]any{{"host": "example-downloads.invalid", "path": "/sbom/abc", "query_redacted": true}})
	h.entry("github_sbom_download", ip(200), nil, doc, nil)
	h.head(after)
}

func spdxPkg(id, name, version, purl string) map[string]any {
	p := map[string]any{"SPDXID": id, "name": name}
	if version != "" {
		p["versionInfo"] = version
	}
	if purl != "" {
		p["externalRefs"] = []any{map[string]any{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": purl}}
	}
	return p
}

func spdxDocument(pkgs ...any) map[string]any {
	return map[string]any{"sbom": map[string]any{"SPDXID": "SPDXRef-DOCUMENT", "spdxVersion": "SPDX-2.3",
		"comment":      "Exact versions could not be resolved for some packages.",
		"creationInfo": map[string]any{"created": "2026-10-14T10:00:00Z", "creators": []any{"Tool: GitHub.com-Dependency-Graph"}},
		"packages":     pkgs,
		"relationships": []any{map[string]any{"spdxElementId": "SPDXRef-DOCUMENT", "relatedSpdxElement": "SPDXRef-github-root", "relationshipType": "DESCRIBES"},
			map[string]any{"spdxElementId": "SPDXRef-github-root", "relatedSpdxElement": "SPDXRef-go-a", "relationshipType": "DEPENDS_ON"}}}}
}

func (h *synthHosted) run(mutate func(map[string]any)) map[string]any {
	h.t.Helper()
	raw, _ := json.Marshal(h.b)
	digest := putStore(h.t, h.fx.store, raw)
	task := v3Task(opGitHubSBOM, hostedRepo, v3Commit, []any{inputRef(digest, "hosted_bundle_manifest")}, func(p map[string]any) {
		p["context"].(map[string]any)["observed_revision"] = nil
		p["context"].(map[string]any)["language"] = "multi"
		if mutate != nil {
			mutate(p)
		}
	})
	status, msg := post(h.t, h.fx.srv, v3Envelope(task, "run-1", false, v3Token()))
	if status != 200 {
		h.t.Fatalf("http %d", status)
	}
	return content(h.t, msg)
}

func scopeDetails(t *testing.T, r map[string]any) map[string]any {
	t.Helper()
	ev := evidenceOf(r, "hosted_sbom_scope")
	if len(ev) != 1 {
		t.Fatalf("one hosted_sbom_scope expected: %d", len(ev))
	}
	return ev[0]["details"].(map[string]any)
}

func historyStates(d map[string]any) []string {
	var out []string
	for _, h := range d["acquisition_history"].([]any) {
		out = append(out, h.(map[string]any)["state"].(string))
	}
	return out
}

// H1: SPDX parse: ranges, no-exact-version comment, unsupported purl type kept, root skipped.
func TestHostedImportParsesRangesRootsAndUnsupportedTypes(t *testing.T) {
	h := newSynthHosted(t)
	h.happy(spdxDocument(
		spdxPkg("SPDXRef-github-root", "github.com/modelcontextprotocol/go-sdk", "", ""),
		spdxPkg("SPDXRef-go-a", "go:github.com/yosida95/uritemplate/v3", "v3.0.2", "pkg:golang/github.com/yosida95/uritemplate/v3@v3.0.2"),
		spdxPkg("SPDXRef-npm-b", "npm:@babel/core", ">= 7.0.0", "pkg:npm/%40babel/core@%3E%3D%207.0.0"),
		spdxPkg("SPDXRef-npm-c", "npm:left-pad", "1.3.0", "pkg:npm/left-pad@1.3.0"),
		spdxPkg("SPDXRef-pip-d", "pip:Jinja2", "3.1.2", "pkg:pypi/Jinja2@3.1.2"),
		spdxPkg("SPDXRef-gha-e", "actions/checkout", "v4", "pkg:githubactions/actions/checkout@v4"),
		spdxPkg("SPDXRef-nover-f", "npm:no-version", "", "pkg:npm/no-version"),
		spdxPkg("SPDXRef-nopurl-g", "mystery", "1.0", ""),
	), 2)
	r := h.run(nil)
	if r["status"] != "complete" {
		t.Fatalf("status %v gaps %v", r["status"], gapReasons(r))
	}
	d := scopeDetails(t, r)
	if d["state"] != "downloaded" || d["revision_binding"] != "unbound" || d["document_binding"] != "unbound" || d["credential_class"] != "unauthenticated" {
		t.Fatalf("scope %v", d)
	}
	if d["spdx_version"] != "SPDX-2.3" || d["created"] != "2026-10-14T10:00:00Z" || !strings.Contains(d["document_comment"].(string), "Exact versions could not be resolved") {
		t.Fatalf("document facts %v", d)
	}
	if fmt.Sprint(historyStates(d)) != "[generate_requested pending pending ready downloaded]" {
		t.Fatalf("history %v", historyStates(d))
	}
	if d["package_count"].(float64) != 7 || d["requested_pin"] != v3Commit || d["head_moved"] != false {
		t.Fatalf("counts/pins %v", d)
	}
	var table struct {
		Rows []hostedRow `json:"rows"`
	}
	raw := decodeArtifact(t, r, 0)
	if err := json.Unmarshal(raw, &table); err != nil {
		t.Fatal(err)
	}
	rows := map[string]hostedRow{}
	for _, row := range table.Rows {
		rows[row.SPDXID] = row
		if row.SourcePath != nil {
			t.Errorf("hosted rows have no source path: %v", row)
		}
	}
	if _, ok := rows["SPDXRef-github-root"]; ok {
		t.Error("the described root package must be skipped")
	}
	want := map[string][3]string{
		"SPDXRef-go-a":     {"Go", "github.com/yosida95/uritemplate/v3", "exact"},
		"SPDXRef-npm-b":    {"npm", "@babel/core", "range"},
		"SPDXRef-npm-c":    {"npm", "left-pad", "exact"},
		"SPDXRef-pip-d":    {"PyPI", "jinja2", "exact"},
		"SPDXRef-gha-e":    {"unsupported_ecosystem", "githubactions/actions/checkout", "unsupported_ecosystem"},
		"SPDXRef-nover-f":  {"npm", "no-version", "missing"},
		"SPDXRef-nopurl-g": {"unsupported_ecosystem", "mystery", "unsupported_ecosystem"},
	}
	for id, w := range want {
		row, ok := rows[id]
		if !ok || row.Ecosystem != w[0] || row.NameNormalized != w[1] || row.VersionState != w[2] {
			t.Errorf("%s: %+v want %v", id, row, w)
		}
	}
	if rows["SPDXRef-pip-d"].NameOriginal != "pip:Jinja2" || rows["SPDXRef-npm-b"].VersionOriginal == nil || *rows["SPDXRef-npm-b"].VersionOriginal != ">= 7.0.0" {
		t.Errorf("original names and version strings are kept verbatim: %+v %+v", rows["SPDXRef-pip-d"], rows["SPDXRef-npm-b"])
	}
	var last string
	for _, row := range table.Rows {
		if last != "" && row.SPDXID < last {
			t.Errorf("rows must be sorted by spdx_id")
		}
		last = row.SPDXID
	}
	cl := claimsOf(r, "hosted_inventory_recorded_unbound")
	if len(cl) != 1 || cl[0]["status"] != "supported" {
		t.Fatalf("claims %v", r["claims"])
	}
}

func decodeArtifact(t *testing.T, r map[string]any, i int) []byte {
	t.Helper()
	a := r["artifacts"].([]any)[i].(map[string]any)
	raw, err := base64.StdEncoding.DecodeString(a["content_b64"].(string))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// H2: a missing or failed exchange is partial, never an empty successful inventory (F1).
func TestHostedImportFailureStatesArePartialNotEmpty(t *testing.T) {
	cases := map[string]struct {
		build  func(h *synthHosted)
		state  string
		reason string
	}{
		"no entries": {func(h *synthHosted) {}, "not_requested", "hosted_not_acquired"},
		"forbidden": {func(h *synthHosted) {
			h.entry("github_sbom_generate", ip(403), nil, map[string]any{"message": "GitHub access to this repository is not enabled for this session"}, nil)
		}, "forbidden", "forbidden"},
		"not found": {func(h *synthHosted) {
			h.entry("github_sbom_generate", ip(404), nil, map[string]any{"message": "Not Found"}, nil)
		}, "not_found", "not_found"},
		"primary rate limit": {func(h *synthHosted) {
			h.entry("github_sbom_generate", ip(403), map[string]string{"x-ratelimit-remaining": "0", "x-ratelimit-reset": "1"}, map[string]any{"message": "API rate limit exceeded"}, nil)
		}, "rate_limited", "rate_limited"},
		"secondary rate limit": {func(h *synthHosted) {
			h.entry("github_sbom_generate", ip(429), map[string]string{"retry-after": "30"}, map[string]any{"message": "secondary rate limit"}, nil)
		}, "rate_limited", "rate_limited"},
		"server error": {func(h *synthHosted) { h.entry("github_sbom_generate", ip(502), nil, []byte("bad gateway"), nil) }, "http_error", "http_error"},
		"foreign sbom_url": {func(h *synthHosted) {
			h.entry("github_sbom_generate", ip(201), nil, map[string]any{"sbom_url": fetchURL("someone/else")}, nil)
		}, "invalid_response", "invalid_response"},
		"foreign host sbom_url": {func(h *synthHosted) {
			h.entry("github_sbom_generate", ip(201), nil, map[string]any{"sbom_url": "https://evil.example/repos/" + hostedRepo + "/dependency-graph/sbom/fetch-report/3fa85f64-5717-4562-b3fc-2c963f66afa6"}, nil)
		}, "invalid_response", "invalid_response"},
		"bad json generate": {func(h *synthHosted) { h.entry("github_sbom_generate", ip(201), nil, []byte("{"), nil) }, "invalid_response", "invalid_response"},
		"poll forbidden": {func(h *synthHosted) {
			h.entry("github_sbom_generate", ip(201), nil, map[string]any{"sbom_url": fetchURL(hostedRepo)}, nil)
			h.entry("github_sbom_poll", ip(403), nil, nil, nil)
		}, "forbidden", "forbidden"},
		"timeout after polls": {func(h *synthHosted) {
			h.entry("github_sbom_generate", ip(201), nil, map[string]any{"sbom_url": fetchURL(hostedRepo)}, nil)
			for i := 0; i < 8; i++ {
				h.entry("github_sbom_poll", ip(202), nil, nil, nil)
			}
		}, "timeout", "timeout"},
		"probe stops at ready": {func(h *synthHosted) {
			h.entry("github_sbom_generate", ip(201), nil, map[string]any{"sbom_url": fetchURL(hostedRepo)}, nil)
			h.entry("github_sbom_poll", ip(302), nil, nil, []map[string]any{{"host": "example-downloads.invalid", "path": "/sbom/abc", "query_redacted": true}})
		}, "ready", "hosted_not_acquired"},
		"download redirected": {func(h *synthHosted) {
			h.entry("github_sbom_generate", ip(201), nil, map[string]any{"sbom_url": fetchURL(hostedRepo)}, nil)
			h.entry("github_sbom_poll", ip(302), nil, nil, []map[string]any{{"host": "example-downloads.invalid", "path": "/p"}})
			h.entry("github_sbom_download", ip(302), nil, nil, nil)
		}, "redirect_refused", "redirect_refused"},
		"download too large": {func(h *synthHosted) {
			h.entry("github_sbom_generate", ip(201), nil, map[string]any{"sbom_url": fetchURL(hostedRepo)}, nil)
			h.entry("github_sbom_poll", ip(302), nil, nil, []map[string]any{{"host": "example-downloads.invalid", "path": "/p"}})
			h.seq++
			h.b.Entries = append(h.b.Entries, hostedEntry{Seq: h.seq, Kind: "github_sbom_download", Status: ip(200), Response: "sha256:" + strings.Repeat("1", 64), Bytes: maxHostedBytes + 1})
		}, "report_too_large", "report_too_large"},
		"event credential": {func(h *synthHosted) {
			h.entry("github_event", nil, nil, map[string]any{"event": "credential_unavailable", "detail": "token required but absent"}, nil)
		}, "credential_unavailable", "credential_unavailable"},
		"event budget": {func(h *synthHosted) {
			h.entry("github_event", nil, nil, map[string]any{"event": "budget", "detail": "request budget reached"}, nil)
		}, "rate_limited", "rate_limited"},
		"event redirect refused": {func(h *synthHosted) {
			h.entry("github_event", nil, nil, map[string]any{"event": "redirect_refused", "detail": "unapproved host", "host": "example-downloads.invalid"}, nil)
		}, "redirect_refused", "redirect_refused"},
		"download without ready": {func(h *synthHosted) {
			h.entry("github_sbom_download", ip(200), nil, spdxDocument(), nil)
		}, "invalid_response", "invalid_response"},
		"unknown event is invalid": {func(h *synthHosted) {
			h.entry("github_event", nil, nil, map[string]any{"event": "downloaded", "detail": "forged"}, nil)
		}, "invalid_response", "invalid_response"},
	}
	for name, c := range cases {
		h := newSynthHosted(t)
		c.build(h)
		r := h.run(nil)
		d := scopeDetails(t, r)
		if r["status"] != "partial" || d["state"] != c.state {
			t.Errorf("%s: status %v state %v want %s", name, r["status"], d["state"], c.state)
			continue
		}
		if len(evidenceOf(r, "hosted_package_table")) != 0 || len(r["artifacts"].([]any)) != 0 || len(r["claims"].([]any)) != 0 {
			t.Errorf("%s: a failed exchange must not yield an empty successful inventory", name)
		}
		me := r["missing_evidence"].([]any)
		if len(me) != 1 || me[0].(map[string]any)["reason"] != c.reason {
			t.Errorf("%s: gaps %v want %s", name, me, c.reason)
		}
		if d["revision_binding"] != "unbound" {
			t.Errorf("%s: %v", name, d)
		}
	}
	// the observed redirect host stays visible in the probe-stage history
	h := newSynthHosted(t)
	h.entry("github_sbom_generate", ip(201), nil, map[string]any{"sbom_url": fetchURL(hostedRepo)}, nil)
	h.entry("github_sbom_poll", ip(302), nil, nil, []map[string]any{{"host": "example-downloads.invalid", "path": "/sbom/abc", "query_redacted": true}})
	d := scopeDetails(t, h.run(nil))
	last := d["acquisition_history"].([]any)
	if m := last[len(last)-1].(map[string]any); m["location_host"] != "example-downloads.invalid" || m["location_path"] != "/sbom/abc" {
		t.Fatalf("history %v", last)
	}
}

// H3: invalid SPDX versions and documents.
func TestHostedImportInvalidDocuments(t *testing.T) {
	for name, c := range map[string]struct {
		doc    any
		state  string
		reason string
	}{
		"spdx 3":        {map[string]any{"sbom": map[string]any{"spdxVersion": "SPDX-3.0", "packages": []any{}}}, "unsupported_spdx_version", "unsupported_spdx_version"},
		"no version":    {map[string]any{"sbom": map[string]any{"packages": []any{}}}, "unsupported_spdx_version", "unsupported_spdx_version"},
		"not json":      {[]byte("<html>"), "invalid_response", "invalid_response"},
		"array":         {[]byte("[1,2]"), "invalid_response", "invalid_response"},
		"deep nesting":  {[]byte(strings.Repeat("[", 100) + strings.Repeat("]", 100)), "invalid_response", "invalid_response"},
		"wrong package": {map[string]any{"sbom": map[string]any{"spdxVersion": "SPDX-2.3", "packages": "x"}}, "invalid_response", "invalid_response"},
	} {
		h := newSynthHosted(t)
		h.happy(c.doc, 0)
		r := h.run(nil)
		d := scopeDetails(t, r)
		if d["state"] != c.state || r["status"] != "partial" || len(evidenceOf(r, "hosted_package_table")) != 0 {
			t.Errorf("%s: state %v status %v", name, d["state"], r["status"])
			continue
		}
		if me := r["missing_evidence"].([]any); len(me) != 1 || me[0].(map[string]any)["reason"] != c.reason {
			t.Errorf("%s: %v", name, me)
		}
	}
}

// Hostile packages are counted, never emitted; duplicate spdx ids are not duplicated.
func TestHostedImportHostilePackagesAreCounted(t *testing.T) {
	h := newSynthHosted(t)
	h.happy(spdxDocument(
		spdxPkg("SPDXRef-ok", "npm:ok", "1.0.0", "pkg:npm/ok@1.0.0"),
		spdxPkg("SPDXRef-ok", "npm:dup", "1.0.0", "pkg:npm/dup@1.0.0"),
		spdxPkg("not-an-spdx-id", "npm:x", "1.0.0", "pkg:npm/x@1.0.0"),
		spdxPkg("SPDXRef-ctl", "npm:bad\nname", "1.0.0", "pkg:npm/x@1.0.0"),
		spdxPkg("SPDXRef-long", strings.Repeat("a", 600), "1.0.0", ""),
		spdxPkg("SPDXRef-ver", "npm:v", "1\n0", "pkg:npm/v@1"),
	), 0)
	r := h.run(nil)
	if r["status"] != "partial" {
		t.Fatalf("status %v", r["status"])
	}
	if cl := claimsOf(r, "hosted_inventory_recorded_unbound"); len(cl) != 1 || cl[0]["status"] != "unknown" {
		t.Fatalf("a partly recorded hosted inventory is not asserted complete: %v", cl)
	}
	var table struct {
		Rows []hostedRow `json:"rows"`
	}
	_ = json.Unmarshal(decodeArtifact(t, r, 0), &table)
	if len(table.Rows) != 1 || table.Rows[0].SPDXID != "SPDXRef-ok" || table.Rows[0].NameOriginal != "npm:ok" {
		t.Fatalf("rows %v", table.Rows)
	}
}

// Head observations never bind: a moved head is recorded and the document stays unbound.
func TestHostedImportHeadMovedStaysUnbound(t *testing.T) {
	h := newSynthHosted(t)
	h.happyAfter(spdxDocument(spdxPkg("SPDXRef-go-a", "go:x", "v1.0.0", "pkg:golang/x.com/y@v1.0.0")), 0, strings.Repeat("b", 40))
	r := h.run(nil)
	d := scopeDetails(t, r)
	if d["head_moved"] != true || d["revision_binding"] != "unbound" || d["document_binding"] != "unbound" || d["state"] != "downloaded" {
		t.Fatalf("%v", d)
	}
	if d["default_branch_head_before"] != strings.Repeat("a", 40) || d["default_branch_head_after"] != strings.Repeat("b", 40) {
		t.Fatalf("%v", d)
	}
}

func TestHostedImportContextRules(t *testing.T) {
	h := newSynthHosted(t)
	h.happy(spdxDocument(), 0)
	for name, c := range map[string]struct {
		mutate func(map[string]any)
		code   string
	}{
		"observed revision set": {func(p map[string]any) { p["context"].(map[string]any)["observed_revision"] = v3Commit }, "context_mismatch"},
		"other repo":            {func(p map[string]any) { p["context"].(map[string]any)["repo_id"] = "github.com/other/repo" }, "context_mismatch"},
		"other pin":             {func(p map[string]any) { p["context"].(map[string]any)["requested_revision"] = strings.Repeat("c", 40) }, "context_mismatch"},
		"other capture set":     {func(p map[string]any) { p["capture_set_id"] = "sha256:" + strings.Repeat("e", 64) }, "capture_mismatch"},
	} {
		if r := h.run(c.mutate); r["kind"] != "rejection" || r["code"] != c.code {
			t.Errorf("%s: %v", name, r)
		}
	}
}
