package main

// Tests for osv_inventory_match. Inputs are SYNTHETIC (labeled; SYNTH-* ids authored here) except the
// REAL-origin record shapes read from the committed I2 capture (alias/related/severity behavior).

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type synth3 struct {
	t     *testing.T
	fx    v3Fixture
	b     osvBundle3
	count int
}

func newSynth3(t *testing.T) *synth3 {
	fx := newV3Server(t)
	return &synth3{t: t, fx: fx, b: osvBundle3{Schema: "opentrace.i3.osv_bundle/1", Kind: "osv", CaptureSetID: v3Set,
		PlannedQueryDigest: "sha256:" + strings.Repeat("9", 64), QueryKeyForm: osvQueryKeyForm, Records: map[string]osvRecordRef{}}}
}

func (s *synth3) plan(eco, name, version, original string) string {
	key := eco + "|" + name + "|" + version
	s.b.Queries = append(s.b.Queries, osvPlanned3{QueryKey: key, Ecosystem: eco, Name: name, VersionQueried: version, VersionOriginal: original})
	return key
}

func req3(token string, qs ...[3]string) []byte {
	var out []any
	for _, q := range qs {
		item := map[string]any{"package": map[string]any{"name": q[1], "ecosystem": q[0]}, "version": q[2]}
		if token != "" {
			item["page_token"] = token
		}
		out = append(out, item)
	}
	return jsonBytes(map[string]any{"queries": out})
}

func (s *synth3) round(req []byte, status int, resp any) {
	r := osvRound{Request: putStore(s.t, s.fx.store, req), Status: status}
	if resp != nil {
		r.Response = putStore(s.t, s.fx.store, jsonBytes(resp))
	}
	s.b.Rounds = append(s.b.Rounds, r)
}

func (s *synth3) record(id string, status int, body []byte) {
	s.b.Records[id] = osvRecordRef{Digest: putStore(s.t, s.fx.store, body), Status: status}
}

func results3(items ...any) map[string]any { return map[string]any{"results": items} }

func page(token string, ids ...string) map[string]any {
	r := map[string]any{}
	if len(ids) > 0 {
		r["vulns"] = vulnList(ids...)
	}
	if token != "" {
		r["next_page_token"] = token
	}
	return r
}

func (s *synth3) run() map[string]any {
	s.t.Helper()
	raw, _ := json.Marshal(s.b)
	digest := putStore(s.t, s.fx.store, raw)
	task := v3Task(opOSVInventory, "x", v3Commit, []any{inputRef(digest, "osv_bundle_manifest")}, func(p map[string]any) {
		p["context"] = map[string]any{"repo_id": "cohort/mcp", "requested_revision": "sha256:" + strings.Repeat("7", 64), "observed_revision": nil,
			"baseline_id": "baseline", "candidate_id": nil, "language": "multi", "build_scope": buildScopeV3}
	})
	status, msg := post(s.t, s.fx.srv, v3Envelope(task, "run-1", false, v3Token()))
	if status != 200 {
		s.t.Fatalf("http %d", status)
	}
	return content(s.t, msg)
}

func claimsOf(r map[string]any, typ string) []map[string]any {
	var out []map[string]any
	for _, c := range r["claims"].([]any) {
		if m := c.(map[string]any); m["type"] == typ {
			out = append(out, m)
		}
	}
	return out
}

func gapReasons(r map[string]any) map[string]string {
	out := map[string]string{}
	for _, m := range r["missing_evidence"].([]any) {
		g := m.(map[string]any)
		key, _ := g["query_key"].(string)
		out[key+"/"+g["reason"].(string)] = g["detail"].(string)
	}
	return out
}

func evidenceOf(r map[string]any, kind string) []map[string]any {
	var out []map[string]any
	for _, e := range r["evidence"].([]any) {
		if m := e.(map[string]any); m["kind"] == kind {
			out = append(out, m)
		}
	}
	return out
}

func i2Record(t *testing.T, id string) []byte {
	t.Helper()
	root := findRoot(t)
	manifests, _ := filepath.Glob(filepath.Join(root, "evidence", "i2", "captures", "*", "capture_manifest.json"))
	for _, m := range manifests {
		raw, _ := os.ReadFile(m)
		var man struct {
			Captures []struct {
				Kind           string `json:"kind"`
				URL            string `json:"url"`
				ResponseDigest string `json:"response_digest"`
			} `json:"captures"`
		}
		_ = json.Unmarshal(raw, &man)
		for _, c := range man.Captures {
			if c.Kind == "osv_vuln" && strings.HasSuffix(c.URL, "/"+id) {
				b, err := os.ReadFile(filepath.Join(filepath.Dir(m), "blobs", strings.TrimPrefix(c.ResponseDigest, "sha256:")))
				if err != nil {
					t.Fatal(err)
				}
				return b
			}
		}
	}
	t.Fatalf("record %s is not in the committed I2 capture", id)
	return nil
}

// U1: page rounds are merged per query; N-claims need completeness.
func TestOSVInventoryPageRoundsMergedPerQuery(t *testing.T) {
	s := newSynth3(t)
	a := s.plan("npm", "left-pad", "1.3.0", "1.3.0")
	z := s.plan("npm", "zero-pkg", "1.0.0", "1.0.0")
	s.round(req3("", [3]string{"npm", "left-pad", "1.3.0"}, [3]string{"npm", "zero-pkg", "1.0.0"}), 200, results3(page("tok1", "SYNTH-A"), page("")))
	s.round(req3("tok1", [3]string{"npm", "left-pad", "1.3.0"}), 200, results3(page("", "SYNTH-B")))
	s.record("SYNTH-A", 200, synthRecord("SYNTH-A", func(r map[string]any) {
		r["affected"] = []any{map[string]any{"package": map[string]any{"name": "left-pad", "ecosystem": "npm"}}}
	}))
	s.record("SYNTH-B", 200, synthRecord("SYNTH-B", func(r map[string]any) {
		r["affected"] = []any{map[string]any{"package": map[string]any{"name": "left-pad", "ecosystem": "npm"}}}
	}))
	r := s.run()
	if r["status"] != "complete" {
		t.Fatalf("status %v gaps %v", r["status"], gapReasons(r))
	}
	adv := evidenceOf(r, "advisory_match")
	if len(adv) != 2 {
		t.Fatalf("both pages must contribute: %d", len(adv))
	}
	qc := evidenceOf(r, "osv_query_complete")[0]["details"].(map[string]any)["queries"].([]any)
	byKey := map[string]map[string]any{}
	for _, q := range qc {
		byKey[q.(map[string]any)["query_key"].(string)] = q.(map[string]any)
	}
	if byKey[a]["pages"].(float64) != 2 || byKey[a]["returned_count"].(float64) != 2 || byKey[a]["version_state"] != "exact" {
		t.Fatalf("left-pad entry %v", byKey[a])
	}
	zeros := claimsOf(r, "no_advisory_match_returned")
	if len(zeros) != 1 || zeros[0]["query_key"] != z {
		t.Fatalf("only the complete empty query yields a zero-result claim (N1): %v", zeros)
	}
	for _, c := range claimsOf(r, "advisory_matches_version") {
		if c["query_key"] != nil && c["query_key"] != "" {
			t.Errorf("advisory claims carry vuln ids, not query keys: %v", c)
		}
	}
}

// U2/N4: a token that never ends, and the page cap, leave the query incomplete with no zero claim.
func TestOSVInventoryPageTokenLoopAndCap(t *testing.T) {
	s := newSynth3(t)
	k := s.plan("Go", "example.com/m", "v1.0.0", "v1.0.0")
	q := [3]string{"Go", "example.com/m", "v1.0.0"}
	s.round(req3("", q), 200, results3(page("t0", "SYNTH-1")))
	for i := 1; i <= 10; i++ {
		s.round(req3(fmt.Sprintf("t%d", i-1), q), 200, results3(page(fmt.Sprintf("t%d", i), "SYNTH-1")))
	}
	s.record("SYNTH-1", 200, synthRecord("SYNTH-1", nil))
	r := s.run()
	if _, ok := gapReasons(r)[k+"/incomplete_query"]; !ok {
		t.Fatalf("gaps %v", gapReasons(r))
	}
	if len(claimsOf(r, "no_advisory_match_returned")) != 0 {
		t.Fatal("an incomplete query must never yield a zero-result claim (N4)")
	}
	// the same with a trailing token and no further round
	s2 := newSynth3(t)
	k2 := s2.plan("Go", "example.com/m", "v1.0.0", "v1.0.0")
	s2.round(req3("", q), 200, results3(page("more")))
	if _, ok := gapReasons(s2.run())[k2+"/incomplete_query"]; !ok {
		t.Fatal("a leftover next_page_token must leave the query incomplete")
	}
}

// U3/N3: a withdrawn-only result is not an empty result.
func TestOSVInventoryWithdrawnOnlyIsNotEmpty(t *testing.T) {
	s := newSynth3(t)
	s.plan("PyPI", "jinja2", "3.1.2", "3.1.2")
	s.round(req3("", [3]string{"PyPI", "jinja2", "3.1.2"}), 200, results3(page("", "SYNTH-W")))
	s.record("SYNTH-W", 200, synthRecord("SYNTH-W", func(r map[string]any) {
		r["withdrawn"] = "2026-02-01T00:00:00Z"
		r["affected"] = []any{map[string]any{"package": map[string]any{"name": "Jinja2", "ecosystem": "PyPI"}}}
	}))
	r := s.run()
	if len(claimsOf(r, "no_advisory_match_returned")) != 0 {
		t.Fatal("a withdrawn-only result must not yield a zero-result claim (N3)")
	}
	if len(claimsOf(r, "advisory_matches_version")) != 0 {
		t.Fatal("a withdrawn record must not be a supported match")
	}
	adv := evidenceOf(r, "advisory_match")
	if len(adv) != 1 || adv[0]["details"].(map[string]any)["withdrawn"] != true {
		t.Fatalf("the withdrawn record must be visible: %v", adv)
	}
	qc := evidenceOf(r, "osv_query_complete")[0]["details"].(map[string]any)["queries"].([]any)[0].(map[string]any)
	if qc["returned_count"].(float64) != 1 || qc["active_count"].(float64) != 0 {
		t.Fatalf("counts %v", qc)
	}
}

// U4: a missing record keeps the ID and blocks the zero claim.
func TestOSVInventoryMissingRecordIsKept(t *testing.T) {
	s := newSynth3(t)
	k := s.plan("Go", "example.com/m", "v1.0.0", "v1.0.0")
	s.round(req3("", [3]string{"Go", "example.com/m", "v1.0.0"}), 200, results3(page("", "SYNTH-GONE", "SYNTH-500")))
	s.record("SYNTH-500", 500, []byte("boom"))
	r := s.run()
	gaps := gapReasons(r)
	if _, ok := gaps[k+"/record_unavailable"]; !ok {
		t.Fatalf("gaps %v", gaps)
	}
	if len(claimsOf(r, "no_advisory_match_returned")) != 0 {
		t.Fatal("unavailable records must block the zero-result claim")
	}
	if r["status"] != "partial" {
		t.Fatalf("status %v", r["status"])
	}
}

// U5/U6 with REAL record shapes from the committed I2 capture: alias vs related and severity forms.
func TestOSVInventoryAliasRelatedAndSeverityRealShapes(t *testing.T) {
	s := newSynth3(t)
	k := s.plan("Go", "golang.org/x/text", "0.3.7", "v0.3.7")
	s.round(req3("", [3]string{"Go", "golang.org/x/text", "0.3.7"}), 200, results3(page("", "GHSA-69ch-w2m2-3vjp", "GO-2022-1059")))
	s.record("GHSA-69ch-w2m2-3vjp", 200, i2Record(t, "GHSA-69ch-w2m2-3vjp"))
	s.record("GO-2022-1059", 200, i2Record(t, "GO-2022-1059"))
	r := s.run()
	byID := map[string]map[string]any{}
	for _, e := range evidenceOf(r, "advisory_match") {
		d := e["details"].(map[string]any)
		byID[d["vuln_id"].(string)] = d
	}
	g, o := byID["GHSA-69ch-w2m2-3vjp"], byID["GO-2022-1059"]
	if g == nil || o == nil {
		t.Fatalf("both records must be matched: %v", byID)
	}
	if fmt.Sprint(g["aliases"]) != "[CVE-2022-32149 GO-2022-1059]" || fmt.Sprint(g["related"]) != "[]" {
		t.Fatalf("GHSA aliases/related %v %v", g["aliases"], g["related"])
	}
	if fmt.Sprint(o["related"]) != "[CGA-wf56-6rqf-4crj]" || fmt.Sprint(o["aliases"]) != "[CVE-2022-32149 GHSA-69ch-w2m2-3vjp]" {
		t.Fatalf("GO aliases/related %v %v", o["aliases"], o["related"])
	}
	if g["database_specific_severity"] != "HIGH" || fmt.Sprint(g["severity"]) == "unknown" {
		t.Fatalf("recorded severity must be preserved: %v", g)
	}
	if o["severity"] != "unknown" || o["database_specific_severity"] != nil {
		t.Fatalf("an absent severity is the string unknown, never 0: %v", o)
	}
	if g["range_check"] != "consistent" || g["version_original"] != "v0.3.7" || g["version_queried"] != "0.3.7" || g["ecosystem"] != "Go" {
		t.Fatalf("extended advisory fields %v", g)
	}
	if len(claimsOf(r, "advisory_matches_version")) != 2 || r["status"] != "complete" {
		t.Fatalf("claims %d status %v gaps %v", len(claimsOf(r, "advisory_matches_version")), r["status"], gapReasons(r))
	}
	_ = k
}

// U7/F3: whole-batch HTTP 400 and index isolation: the captured failed round, the resubmitted remainder.
func TestOSVInventoryBatchRejectionIsolation(t *testing.T) {
	s := newSynth3(t)
	good1 := s.plan("npm", "left-pad", "1.3.0", "1.3.0")
	bad := s.plan("npm", "bad-pkg", "9.9.9", "9.9.9")
	good2 := s.plan("npm", "zero-pkg", "1.0.0", "1.0.0")
	all := [][3]string{{"npm", "left-pad", "1.3.0"}, {"npm", "bad-pkg", "9.9.9"}, {"npm", "zero-pkg", "1.0.0"}}
	s.round(req3("", all...), 400, map[string]any{"code": 3, "message": "error in query at index 1: invalid"})
	s.round(req3("", all[0], all[2]), 200, results3(page(""), page("")))
	r := s.run()
	gaps := gapReasons(r)
	if _, ok := gaps[bad+"/query_rejected"]; !ok {
		t.Fatalf("the isolated query must be query_rejected: %v", gaps)
	}
	zeros := map[string]bool{}
	for _, c := range claimsOf(r, "no_advisory_match_returned") {
		zeros[c["query_key"].(string)] = true
	}
	if !zeros[good1] || !zeros[good2] || zeros[bad] || len(zeros) != 2 {
		t.Fatalf("the remainder completes, the rejected query never yields a zero claim: %v", zeros)
	}
	if r["status"] != "partial" {
		t.Fatalf("status %v", r["status"])
	}
	// a 400 that names no index leaves every query of the batch unknown
	s2 := newSynth3(t)
	s2.plan("npm", "a", "1.0.0", "1.0.0")
	s2.plan("npm", "b", "1.0.0", "1.0.0")
	s2.round(req3("", [3]string{"npm", "a", "1.0.0"}, [3]string{"npm", "b", "1.0.0"}), 400, map[string]any{"code": 3, "message": "bad"})
	r2 := s2.run()
	if r2["status"] != "failed" || len(r2["claims"].([]any)) != 0 {
		t.Fatalf("a wholly rejected batch evaluates nothing: %v", r2["status"])
	}
}

// U8: the key form comes from the captured request; bare and v-prefixed Go forms.
func TestOSVInventoryKeyFormFromCapturedRequest(t *testing.T) {
	for _, form := range []string{"0.3.7", "v0.3.7"} {
		s := newSynth3(t)
		k := s.plan("Go", "golang.org/x/text", form, "v0.3.7")
		s.round(req3("", [3]string{"Go", "golang.org/x/text", form}), 200, results3(page("")))
		r := s.run()
		zeros := claimsOf(r, "no_advisory_match_returned")
		if len(zeros) != 1 || zeros[0]["query_key"] != k || k != "Go|golang.org/x/text|"+form {
			t.Errorf("form %s: %v %s", form, zeros, k)
		}
	}
	// a planned form that differs from the captured request is unseen, never silently matched
	s := newSynth3(t)
	k := s.plan("Go", "golang.org/x/text", "v0.3.7", "v0.3.7")
	s.round(req3("", [3]string{"Go", "golang.org/x/text", "0.3.7"}), 200, results3(page("")))
	if _, ok := gapReasons(s.run())[k+"/incomplete_query"]; !ok {
		t.Fatal("a key that is not in the captured request must stay incomplete")
	}
}

// U9/U10: PyPI case variants join to one identity but keep the original; npm scoped names.
func TestOSVInventoryPyPIAndScopedNames(t *testing.T) {
	s := newSynth3(t)
	k := s.plan("PyPI", "jinja2", "3.1.2", "3.1.2")
	n := s.plan("npm", "@babel/core", "7.0.0", "7.0.0")
	s.round(req3("", [3]string{"PyPI", "Jinja2", "3.1.2"}, [3]string{"npm", "@babel/core", "7.0.0"}), 200, results3(page("", "SYNTH-J"), page("")))
	s.record("SYNTH-J", 200, synthRecord("SYNTH-J", func(r map[string]any) {
		r["affected"] = []any{map[string]any{"package": map[string]any{"name": "Jinja2", "ecosystem": "PyPI"},
			"ranges": []any{map[string]any{"type": "ECOSYSTEM", "events": []any{map[string]any{"introduced": "0"}, map[string]any{"fixed": "3.1.3"}}}}}}
	}))
	r := s.run()
	adv := evidenceOf(r, "advisory_match")
	if len(adv) != 1 {
		t.Fatalf("PyPI case variants must join: %d, gaps %v", len(adv), gapReasons(r))
	}
	d := adv[0]["details"].(map[string]any)
	if d["query_key"] != k || d["package"] != "jinja2" || d["range_check"] != "not_evaluated" {
		t.Fatalf("details %v", d)
	}
	zeros := claimsOf(r, "no_advisory_match_returned")
	if len(zeros) != 1 || zeros[0]["query_key"] != n {
		t.Fatalf("scoped npm zero claim: %v", zeros)
	}
}

// N2/N5 and the hostile planning checks: a positive result never yields a zero claim; invalid names or
// versions are never a query component.
func TestOSVInventoryNegativeClaimsAndHostilePlans(t *testing.T) {
	s := newSynth3(t)
	s.plan("npm", "left-pad", "1.3.0", "1.3.0")
	s.round(req3("", [3]string{"npm", "left-pad", "1.3.0"}), 200, results3(page("", "SYNTH-P")))
	s.record("SYNTH-P", 200, synthRecord("SYNTH-P", func(r map[string]any) {
		r["affected"] = []any{map[string]any{"package": map[string]any{"name": "left-pad", "ecosystem": "npm"}}}
	}))
	if r := s.run(); len(claimsOf(r, "no_advisory_match_returned")) != 0 || len(claimsOf(r, "advisory_matches_version")) != 1 {
		t.Fatal("a positive result never yields the zero-result claim (N2)")
	}
	hostile := map[string]osvPlanned3{
		"newline in version": {"npm|a|1\n", "npm", "a", "1\n", "1"},
		"dotdot go path":     {"Go|a b|v1", "Go", "a b", "v1", "v1"},
		"shell name":         {"npm|a;rm|1", "npm", "a;rm", "1", "1"},
		"empty version":      {"npm|a|", "npm", "a", "", ""},
		"key mismatch":       {"npm|zzz|1", "npm", "a", "1", "1"},
		"unknown ecosystem":  {"Maven|a|1", "Maven", "a", "1", "1"},
		"long version":       {"npm|a|" + strings.Repeat("1", 200), "npm", "a", strings.Repeat("1", 200), "1"},
		"pypi unnormalized":  {"PyPI|Jinja2|1", "PyPI", "Jinja2", "1", "1"},
	}
	for name, p := range hostile {
		h := newSynth3(t)
		h.b.Queries = []osvPlanned3{p}
		task := v3Task(opOSVInventory, "x", v3Commit, nil, nil)
		_ = task
		raw, _ := json.Marshal(h.b)
		digest := putStore(t, h.fx.store, raw)
		task = v3Task(opOSVInventory, "x", v3Commit, []any{inputRef(digest, "osv_bundle_manifest")}, func(m map[string]any) {
			m["context"] = map[string]any{"repo_id": "cohort/mcp", "requested_revision": "sha256:" + strings.Repeat("7", 64), "observed_revision": nil,
				"baseline_id": "baseline", "candidate_id": nil, "language": "multi", "build_scope": buildScopeV3}
		})
		_, msg := post(t, h.fx.srv, v3Envelope(task, "run-1", false, v3Token()))
		if c := content(t, msg); c["kind"] != "rejection" || c["code"] != "invalid_request" {
			t.Errorf("%s: %v", name, c)
		}
	}
	// more than 100 planned queries and duplicates
	big := newSynth3(t)
	for i := 0; i < 101; i++ {
		big.plan("npm", fmt.Sprintf("pkg-%d", i), "1.0.0", "1.0.0")
	}
	raw, _ := json.Marshal(big.b)
	digest := putStore(t, big.fx.store, raw)
	task := v3Task(opOSVInventory, "x", v3Commit, []any{inputRef(digest, "osv_bundle_manifest")}, func(m map[string]any) {
		m["context"] = map[string]any{"repo_id": "cohort/mcp", "requested_revision": "sha256:" + strings.Repeat("7", 64), "observed_revision": nil,
			"baseline_id": "baseline", "candidate_id": nil, "language": "multi", "build_scope": buildScopeV3}
	})
	_, msg := post(t, big.fx.srv, v3Envelope(task, "run-1", false, v3Token()))
	if c := content(t, msg); c["code"] != "invalid_request" {
		t.Errorf("101 queries: %v", c)
	}
}

// F4: the evidence budget marks the rest output_limit, never drops them, and stays under the result caps.
func TestOSVInventoryOutputLimitMarksTheRest(t *testing.T) {
	s := newSynth3(t)
	var qs [][3]string
	for i := 0; i < 100; i++ {
		name := fmt.Sprintf("pkg-%03d", i)
		s.plan("npm", name, "1.0.0", "1.0.0")
		qs = append(qs, [3]string{"npm", name, "1.0.0"})
	}
	ids := []string{}
	for i := 0; i < 5; i++ {
		ids = append(ids, fmt.Sprintf("SYNTH-%d", i))
	}
	var items []any
	for range qs {
		items = append(items, page("", ids...))
	}
	s.round(req3("", qs...), 200, results3(items...))
	for _, id := range ids {
		s.record(id, 200, synthRecord(id, func(r map[string]any) {
			r["affected"] = []any{map[string]any{"package": map[string]any{"name": "x", "ecosystem": "npm"}}}
		}))
	}
	r := s.run()
	ev, cl := len(r["evidence"].([]any)), len(r["claims"].([]any))
	if ev+cl > osvItemBudget || ev > 1000 || cl > 1000 {
		t.Fatalf("budget exceeded: %d evidence %d claims", ev, cl)
	}
	limited := 0
	for k := range gapReasons(r) {
		if strings.HasSuffix(k, "/output_limit") {
			limited++
		}
	}
	if limited == 0 || r["status"] != "partial" {
		t.Fatalf("the remaining queries must be output_limit gaps: %d status %v", limited, r["status"])
	}
	reported := len(evidenceOf(r, "osv_query_complete")[0]["details"].(map[string]any)["queries"].([]any))
	if reported+limited != 100 {
		t.Fatalf("every planned query is either reported or marked: %d + %d", reported, limited)
	}
}

func TestOSVInventoryContextAndCaptureChecks(t *testing.T) {
	s := newSynth3(t)
	s.plan("npm", "a", "1.0.0", "1.0.0")
	s.round(req3("", [3]string{"npm", "a", "1.0.0"}), 200, results3(page("")))
	s.b.CaptureSetID = "sha256:" + strings.Repeat("d", 64)
	raw, _ := json.Marshal(s.b)
	digest := putStore(t, s.fx.store, raw)
	task := v3Task(opOSVInventory, "x", v3Commit, []any{inputRef(digest, "osv_bundle_manifest")}, nil)
	_, msg := post(t, s.fx.srv, v3Envelope(task, "run-1", false, v3Token()))
	if c := content(t, msg); c["code"] != "capture_mismatch" {
		t.Fatalf("%v", c)
	}
	// a v2-style bundle (name@version keys, wrong key form) is not accepted
	s2 := newSynth3(t)
	s2.b.QueryKeyForm = "name@version"
	s2.plan("npm", "a", "1.0.0", "1.0.0")
	raw, _ = json.Marshal(s2.b)
	digest = putStore(t, s2.fx.store, raw)
	task = v3Task(opOSVInventory, "x", v3Commit, []any{inputRef(digest, "osv_bundle_manifest")}, nil)
	_, msg = post(t, s2.fx.srv, v3Envelope(task, "run-1", false, v3Token()))
	if c := content(t, msg); c["kind"] != "result" || c["status"] != "failed" {
		t.Fatalf("%v", c)
	}
}
