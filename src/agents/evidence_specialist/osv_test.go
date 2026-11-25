package main

// SYNTHETIC inputs (parser/validator behavior only). Nothing here is an OSV capture; the IDs are
// SYNTH-* and the records are authored in this file. They support no claim about OSV content.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

const synthCaptureSet = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

func putBlob(t *testing.T, store string, data []byte) string {
	t.Helper()
	sum := sha256.Sum256(data)
	hexd := hex.EncodeToString(sum[:])
	if err := os.MkdirAll(filepath.Join(store, "sha256"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(store, "sha256", hexd), data, 0o444); err != nil {
		t.Fatal(err)
	}
	return "sha256:" + hexd
}

func jsonBytes(v any) []byte { b, _ := json.Marshal(v); return b }

func synthRecord(id string, mutate func(map[string]any)) []byte {
	rec := map[string]any{"id": id, "modified": "2026-01-01T00:00:00Z", "published": "2026-01-01T00:00:00Z",
		"aliases": []any{"SYNTH-ALIAS-" + id}, "summary": "SYNTHETIC",
		"affected": []any{map[string]any{"package": map[string]any{"name": "golang.org/x/text", "ecosystem": "Go"},
			"ranges": []any{map[string]any{"type": "SEMVER", "events": []any{map[string]any{"introduced": "0"}, map[string]any{"fixed": "0.3.8"}}}}}}}
	if mutate != nil {
		mutate(rec)
	}
	return jsonBytes(rec)
}

func osvRequest(queries ...[2]string) []byte {
	var qs []any
	for _, q := range queries {
		qs = append(qs, map[string]any{"package": map[string]any{"name": q[0], "ecosystem": "Go"}, "version": q[1]})
	}
	return jsonBytes(map[string]any{"queries": qs})
}

type synthOSV struct {
	t       *testing.T
	store   string
	bundle  osvBundle
	planned []osvPlanned
}

func newSynthOSV(t *testing.T, store string) *synthOSV {
	return &synthOSV{t: t, store: store, bundle: osvBundle{Schema: "opentrace.bundle_manifest/1", Kind: "osv",
		CaptureSetID: synthCaptureSet, Records: map[string]osvRecordRef{}}}
}

func (s *synthOSV) round(req []byte, status int, resp any) {
	r := osvRound{Request: putBlob(s.t, s.store, req), Status: status}
	if resp != nil {
		r.Response = putBlob(s.t, s.store, jsonBytes(resp))
	}
	s.bundle.Rounds = append(s.bundle.Rounds, r)
}

func (s *synthOSV) record(id string, status int, body []byte) {
	s.bundle.Records[id] = osvRecordRef{Digest: putBlob(s.t, s.store, body), Status: status}
}

func (s *synthOSV) plan(module, version, skip string) {
	s.bundle.Queries = append(s.bundle.Queries, osvPlanned{QueryKey: module + "@" + version, Module: module, Version: version, SkipReason: skip})
}

func (s *synthOSV) digest() string { return putBlob(s.t, s.store, jsonBytes(s.bundle)) }

func vulnList(ids ...string) []any {
	var out []any
	for _, id := range ids {
		out = append(out, map[string]any{"id": id, "modified": "2026-01-01T00:00:00Z"})
	}
	return out
}

func osvTask(bundleDigest string, mutate func(map[string]any)) map[string]any {
	return v2Task(func(p map[string]any) {
		p["operations"] = []any{opOSV}
		p["capture_set_id"] = synthCaptureSet
		p["inputs"] = []any{
			map[string]any{"digest": fixtureDigest, "media_type": "text/plain", "role": "source_manifest"},
			map[string]any{"digest": bundleDigest, "media_type": "application/json", "role": "osv_bundle_manifest"}}
		if mutate != nil {
			mutate(p)
		}
	})
}

func osvResult(t *testing.T, mk func(s *synthOSV)) map[string]any {
	t.Helper()
	srv, store := newTestServer(t, fixtureGoMod)
	s := newSynthOSV(t, store)
	mk(s)
	status, msg := post(t, srv, v2Envelope(osvTask(s.digest(), nil), "run-1", false, true))
	if status != 200 {
		t.Fatalf("status %d", status)
	}
	return content(t, msg)
}

func claimTypes(res map[string]any) map[string][]map[string]any {
	out := map[string][]map[string]any{}
	for _, c := range res["claims"].([]any) {
		m := c.(map[string]any)
		out[m["type"].(string)] = append(out[m["type"].(string)], m)
	}
	return out
}

func reasons(res map[string]any) []string {
	var out []string
	for _, m := range res["missing_evidence"].([]any) {
		out = append(out, m.(map[string]any)["reason"].(string))
	}
	return out
}

func TestOSVPositiveCompleteQuery(t *testing.T) {
	res := osvResult(t, func(s *synthOSV) {
		s.plan("golang.org/x/text", "0.3.7", "")
		s.round(osvRequest([2]string{"golang.org/x/text", "0.3.7"}), 200, map[string]any{"results": []any{map[string]any{"vulns": vulnList("SYNTH-0001")}}})
		s.record("SYNTH-0001", 200, synthRecord("SYNTH-0001", nil))
	})
	if res["status"] != "complete" || res["schema_version"] != "2.0" || res["capture_set_id"] != synthCaptureSet {
		t.Fatalf("result %v", res)
	}
	claims := claimTypes(res)
	if len(claims["advisory_matches_version"]) != 1 || claims["advisory_matches_version"][0]["vuln_id"] != "SYNTH-0001" {
		t.Fatalf("claims %v", claims)
	}
	if len(claims["no_advisory_match_returned"]) != 0 {
		t.Fatal("a complete POSITIVE query must never yield no_advisory_match_returned (N1)")
	}
	var detail map[string]any
	for _, e := range res["evidence"].([]any) {
		if e.(map[string]any)["kind"] == "advisory_match" {
			detail = e.(map[string]any)["details"].(map[string]any)
		}
	}
	if detail["range_check"] != "consistent" || detail["severity"] != "unknown" || detail["withdrawn"] != false {
		t.Fatalf("details %v", detail)
	}
}

func TestOSVZeroResultNeedsCompleteEmptyQuery(t *testing.T) {
	res := osvResult(t, func(s *synthOSV) {
		s.plan("golang.org/x/text", "0.41.0", "")
		s.round(osvRequest([2]string{"golang.org/x/text", "0.41.0"}), 200, map[string]any{"results": []any{map[string]any{}}})
	})
	claims := claimTypes(res)
	z := claims["no_advisory_match_returned"]
	if res["status"] != "complete" || len(z) != 1 || z[0]["proposition"] != emptyResultText || z[0]["query_key"] != "golang.org/x/text@0.41.0" {
		t.Fatalf("U4: %v", res)
	}
}

func TestOSVIncompletePaginationIsExplicit(t *testing.T) {
	res := osvResult(t, func(s *synthOSV) { // U1: next_page_token with no second round captured
		s.plan("golang.org/x/text", "0.3.7", "")
		s.round(osvRequest([2]string{"golang.org/x/text", "0.3.7"}), 200,
			map[string]any{"results": []any{map[string]any{"vulns": vulnList("SYNTH-0001"), "next_page_token": "tok"}}})
		s.record("SYNTH-0001", 200, synthRecord("SYNTH-0001", nil))
	})
	if res["status"] != "partial" || len(reasons(res)) != 1 || reasons(res)[0] != "incomplete_query" {
		t.Fatalf("U1: %v", res)
	}
	if len(claimTypes(res)["no_advisory_match_returned"]) != 0 {
		t.Fatal("incomplete query produced an empty-result claim")
	}
	// the IDs that did arrive are kept
	if len(claimTypes(res)["advisory_matches_version"]) != 1 {
		t.Fatal("returned IDs were dropped")
	}
}

func TestOSVPaginationCompletesAcrossRounds(t *testing.T) {
	res := osvResult(t, func(s *synthOSV) {
		s.plan("golang.org/x/text", "0.3.7", "")
		q := [2]string{"golang.org/x/text", "0.3.7"}
		s.round(osvRequest(q), 200, map[string]any{"results": []any{map[string]any{"vulns": vulnList("SYNTH-0001"), "next_page_token": "tok"}}})
		s.round(osvRequest(q), 200, map[string]any{"results": []any{map[string]any{"vulns": vulnList("SYNTH-0002")}}})
		s.record("SYNTH-0001", 200, synthRecord("SYNTH-0001", nil))
		s.record("SYNTH-0002", 200, synthRecord("SYNTH-0002", nil))
	})
	if res["status"] != "complete" || len(claimTypes(res)["advisory_matches_version"]) != 2 {
		t.Fatalf("two-page query: %v", res)
	}
}

func TestOSVVersionMissingIsNotQueried(t *testing.T) {
	res := osvResult(t, func(s *synthOSV) { // U2
		s.plan("example.com/local/dep", "", "version_missing")
		s.plan("golang.org/x/text", "0.41.0", "")
		s.round(osvRequest([2]string{"golang.org/x/text", "0.41.0"}), 200, map[string]any{"results": []any{map[string]any{}}})
	})
	if res["status"] != "partial" || len(reasons(res)) != 1 || reasons(res)[0] != "version_missing" {
		t.Fatalf("U2: %v", res)
	}
	// the other query's empty result is still reportable, the skipped one is not
	if len(claimTypes(res)["no_advisory_match_returned"]) != 1 {
		t.Fatalf("U2 claims: %v", claimTypes(res))
	}
}

func TestOSVRecordUnavailableKeepsTheIDAndBlocksEmptyClaims(t *testing.T) {
	res := osvResult(t, func(s *synthOSV) { // U3
		s.plan("golang.org/x/text", "0.3.7", "")
		s.round(osvRequest([2]string{"golang.org/x/text", "0.3.7"}), 200, map[string]any{"results": []any{map[string]any{"vulns": vulnList("SYNTH-0001", "SYNTH-0002")}}})
		s.record("SYNTH-0001", 404, []byte(`{"code":5,"message":"Bug not found."}`))
		s.record("SYNTH-0002", 200, synthRecord("SYNTH-0002", nil))
	})
	if res["status"] != "partial" || len(reasons(res)) != 1 || reasons(res)[0] != "record_unavailable" {
		t.Fatalf("U3: %v", res)
	}
	var qc map[string]any
	for _, e := range res["evidence"].([]any) {
		if e.(map[string]any)["kind"] == "osv_query_complete" {
			qc = e.(map[string]any)["details"].(map[string]any)["queries"].([]any)[0].(map[string]any)
		}
	}
	if qc["returned_count"].(float64) != 2 || qc["active_count"].(float64) != 1 {
		t.Fatalf("the unavailable ID must still count as returned: %v", qc)
	}
}

func TestOSVWithdrawnSeverityAndRelated(t *testing.T) {
	res := osvResult(t, func(s *synthOSV) { // U5 and N2 (only withdrawn records)
		s.plan("golang.org/x/text", "0.3.7", "")
		s.round(osvRequest([2]string{"golang.org/x/text", "0.3.7"}), 200, map[string]any{"results": []any{map[string]any{"vulns": vulnList("SYNTH-0001")}}})
		s.record("SYNTH-0001", 200, synthRecord("SYNTH-0001", func(r map[string]any) {
			r["withdrawn"] = "2026-02-01T00:00:00Z"
			r["related"] = []any{"SYNTH-REL-1"}
			r["severity"] = []any{map[string]any{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N"}}
		}))
	})
	claims := claimTypes(res)
	if len(claims["advisory_matches_version"]) != 0 || len(claims["no_advisory_match_returned"]) != 0 {
		t.Fatalf("N2: withdrawn-only result must give neither a match nor an empty claim: %v", claims)
	}
	var d map[string]any
	for _, e := range res["evidence"].([]any) {
		if e.(map[string]any)["kind"] == "advisory_match" {
			d = e.(map[string]any)["details"].(map[string]any)
		}
	}
	if d["withdrawn"] != true || len(d["related"].([]any)) != 1 || len(d["aliases"].([]any)) != 1 || d["severity"] == "unknown" {
		t.Fatalf("U5 details: %v", d)
	}
	if aliases := d["aliases"].([]any); aliases[0] == "SYNTH-REL-1" {
		t.Fatal("related merged into aliases")
	}
	if len(res["warnings"].([]any)) != 1 {
		t.Fatalf("warnings %v", res["warnings"])
	}
}

func TestOSVRangeCheckStates(t *testing.T) {
	cases := []struct {
		name, version string
		mutate        func(map[string]any)
		want          string
	}{
		{"affected", "0.3.7", nil, "consistent"},
		{"fixed boundary excluded", "0.3.8", nil, "inconsistent"},
		{"pseudo-version not evaluated", "0.0.0-20200101000000-abcdefabcdef", nil, "not_evaluated"},
		{"non-semver range", "0.3.7", func(r map[string]any) {
			r["affected"].([]any)[0].(map[string]any)["ranges"].([]any)[0].(map[string]any)["type"] = "GIT"
		}, "not_evaluated"},
		{"last_affected inclusive", "0.3.7", func(r map[string]any) {
			r["affected"].([]any)[0].(map[string]any)["ranges"].([]any)[0].(map[string]any)["events"] =
				[]any{map[string]any{"introduced": "0.3.0"}, map[string]any{"last_affected": "0.3.7"}}
		}, "consistent"},
		{"open interval", "9.9.9", func(r map[string]any) {
			r["affected"].([]any)[0].(map[string]any)["ranges"].([]any)[0].(map[string]any)["events"] = []any{map[string]any{"introduced": "1.0.0"}}
		}, "consistent"},
		{"other module", "0.3.7", func(r map[string]any) {
			r["affected"].([]any)[0].(map[string]any)["package"].(map[string]any)["name"] = "example.com/other"
		}, "not_evaluated"},
	}
	for _, tc := range cases {
		var rec osvRecord
		if err := json.Unmarshal(synthRecord("SYNTH-1", tc.mutate), &rec); err != nil {
			t.Fatal(err)
		}
		got, _ := rangeCheck(&rec, "golang.org/x/text", tc.version)
		if got != tc.want {
			t.Errorf("%s: got %s want %s", tc.name, got, tc.want)
		}
	}
}

func TestOSVInconsistentRangeDowngradesTheClaim(t *testing.T) {
	res := osvResult(t, func(s *synthOSV) {
		s.plan("golang.org/x/text", "0.3.8", "")
		s.round(osvRequest([2]string{"golang.org/x/text", "0.3.8"}), 200, map[string]any{"results": []any{map[string]any{"vulns": vulnList("SYNTH-0001")}}})
		s.record("SYNTH-0001", 200, synthRecord("SYNTH-0001", nil)) // fixed in 0.3.8: not affected at 0.3.8
	})
	c := claimTypes(res)["advisory_matches_version"]
	if len(c) != 1 || c[0]["status"] != "unknown" {
		t.Fatalf("inconsistent range must not be a supported claim: %v", c)
	}
}

func TestOSVRoundFailureMakesQueriesIncomplete(t *testing.T) {
	res := osvResult(t, func(s *synthOSV) {
		s.plan("golang.org/x/text", "0.3.7", "")
		s.round(osvRequest([2]string{"golang.org/x/text", "0.3.7"}), 503, nil)
	})
	if res["status"] != "failed" || len(reasons(res)) != 1 || reasons(res)[0] != "incomplete_query" {
		t.Fatalf("round failure: %v", res)
	}
	if len(claimTypes(res)["no_advisory_match_returned"]) != 0 {
		t.Fatal("a failed fetch is not a zero result")
	}
}

func TestOSVResultCountMismatchIsIncomplete(t *testing.T) {
	res := osvResult(t, func(s *synthOSV) {
		s.plan("golang.org/x/text", "0.3.7", "")
		s.round(osvRequest([2]string{"golang.org/x/text", "0.3.7"}), 200, map[string]any{"results": []any{}})
	})
	if reasons(res)[0] != "incomplete_query" {
		t.Fatalf("%v", res)
	}
}

func TestOSVCaptureMismatchAndMissingBundle(t *testing.T) {
	srv, store := newTestServer(t, fixtureGoMod)
	s := newSynthOSV(t, store)
	s.plan("golang.org/x/text", "0.41.0", "")
	s.round(osvRequest([2]string{"golang.org/x/text", "0.41.0"}), 200, map[string]any{"results": []any{map[string]any{}}})
	d := s.digest()
	_, msg := post(t, srv, v2Envelope(osvTask(d, func(p map[string]any) {
		p["capture_set_id"] = "sha256:" + string(make([]byte, 0)) + "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	}), "run-1", false, true))
	if c := content(t, msg); c["code"] != "capture_mismatch" || c["schema_version"] != "2.0" {
		t.Fatalf("capture mismatch: %v", c)
	}
	_, msg = post(t, srv, v2Envelope(osvTask("sha256:"+"0000000000000000000000000000000000000000000000000000000000000000", nil), "run-1", false, true))
	c := content(t, msg)
	if c["status"] != "failed" || reasons(c)[0] != "input_unavailable" {
		t.Fatalf("missing bundle: %v", c)
	}
}

func TestOSVRequirementOfAnotherDimensionStaysUnknown(t *testing.T) {
	srv, store := newTestServer(t, fixtureGoMod)
	s := newSynthOSV(t, store)
	s.plan("golang.org/x/text", "0.41.0", "")
	s.round(osvRequest([2]string{"golang.org/x/text", "0.41.0"}), 200, map[string]any{"results": []any{map[string]any{}}})
	_, msg := post(t, srv, v2Envelope(osvTask(s.digest(), func(p map[string]any) {
		p["requirements"] = []any{map[string]any{"requirement_id": "req-1", "dimension": "inventory"},
			map[string]any{"requirement_id": "req-2", "dimension": "call_path"}}
	}), "run-1", false, true))
	c := content(t, msg)
	if c["status"] != "partial" || reasons(c)[0] != "unsupported_dimension" {
		t.Fatalf("%v", c)
	}
}

func TestOSVPlannedQueriesFilterOtherVersionsInASharedRequest(t *testing.T) {
	res := osvResult(t, func(s *synthOSV) {
		s.plan("golang.org/x/text", "0.3.7", "") // the task concerns the baseline only
		both := osvRequest([2]string{"golang.org/x/text", "0.3.7"}, [2]string{"golang.org/x/text", "0.41.0"})
		s.round(both, 200, map[string]any{"results": []any{map[string]any{"vulns": vulnList("SYNTH-0001")}, map[string]any{}}})
		s.record("SYNTH-0001", 200, synthRecord("SYNTH-0001", nil))
	})
	for _, e := range res["evidence"].([]any) {
		if e.(map[string]any)["kind"] == "osv_query_complete" {
			qs := e.(map[string]any)["details"].(map[string]any)["queries"].([]any)
			if len(qs) != 1 || qs[0].(map[string]any)["query_key"] != "golang.org/x/text@0.3.7" {
				t.Fatalf("other versions leaked into the task: %v", qs)
			}
		}
	}
	if len(claimTypes(res)["no_advisory_match_returned"]) != 0 {
		t.Fatal("the other version's empty result leaked into this task")
	}
}
