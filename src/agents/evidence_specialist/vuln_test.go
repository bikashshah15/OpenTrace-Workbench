package main

// Parser tests over SYNTHETIC govulncheck streams (testdata/govulncheck/README.md). The stream
// shapes are real govulncheck v1.1.4 output for a synthetic database; no real advisory is involved.

import (
	"os"
	"strings"
	"testing"
)

func readTestdata(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/govulncheck/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func vulnTask() *TaskRequest {
	one, big := 1, 1<<20
	return &TaskRequest{TaskID: "tv", RunID: "run-tv", CaptureSetID: synthCaptureSet,
		Context: Context{RequestedRevision: "sha256:" + strings.Repeat("a", 64)}, Budget: &Budget{MaxWorkerJobs: &one, MaxProducedArtifactBytes: &big}}
}

func buildFrom(t *testing.T, data []byte) (*Result, *vulnStream) {
	t.Helper()
	st, err := parseVulnStream(data)
	if err := streamComplete(st, err, 0); err != nil {
		t.Fatalf("stream should be complete: %v", err)
	}
	res := &Result{Evidence: []EvidenceItem{}, Claims: []Claim{}}
	buildVulnEvidence(res, vulnTask(), st, ArtifactRef{Digest: "sha256:" + strings.Repeat("b", 64), MediaType: "application/json"},
		"sha256:"+strings.Repeat("c", 64), "file://<capture-db>", "2026-10-13T00:00:00.000Z", "govulncheck@v1.1.4", "linux", "amd64")
	return res, st
}

func kinds(res *Result) map[string]int {
	out := map[string]int{}
	for _, e := range res.Evidence {
		out[e.Kind]++
	}
	return out
}

func claimsByType(res *Result) map[string][]Claim {
	out := map[string][]Claim{}
	for _, c := range res.Claims {
		out[c.Type] = append(out[c.Type], c)
	}
	return out
}

func TestVulnStreamLevelsAndEntryFirstTrace(t *testing.T) {
	res, st := buildFrom(t, readTestdata(t, "SYNTHETIC_findings.json"))
	if st.MainModule != "example.com/opentrace/fixture/i2" || st.Config.ScannerVersion != "v1.1.4" {
		t.Fatalf("stream header: %+v %q", st.Config, st.MainModule)
	}
	k := kinds(res)
	if k["govulncheck_scope"] != 1 || k["vuln_module_required"] != 1 || k["vuln_package_imported"] != 1 || k["vuln_call_path"] != 1 {
		t.Fatalf("evidence kinds %v", k)
	}
	for _, e := range res.Evidence {
		switch e.Kind {
		case "vuln_call_path":
			if e.Dimension != "call_path" {
				t.Fatalf("path dimension %s", e.Dimension)
			}
			trace := e.Details.(map[string]any)["trace"].([]map[string]any)
			// I-VC-1 / S1 shape: main -> Negotiate -> ParseAcceptLanguage, entry first, at least 3 frames.
			if len(trace) < 3 || trace[0]["function"] != "main" || trace[1]["function"] != "Negotiate" ||
				trace[len(trace)-1]["function"] != "ParseAcceptLanguage" {
				t.Fatalf("trace must run entry (main) first: %v", trace)
			}
			if trace[0]["module"] != st.MainModule {
				t.Fatalf("entry frame is not in the main module: %v", trace[0])
			}
		case "vuln_package_imported":
			if e.Dimension != "code_presence" {
				t.Fatalf("package dimension %s", e.Dimension)
			}
		case "vuln_module_required":
			if e.Dimension != "inventory" {
				t.Fatalf("module dimension %s", e.Dimension)
			}
		}
	}
	c := claimsByType(res)
	if len(c["static_call_path_found"]) != 1 || len(c["call_path_not_established"]) != 0 {
		t.Fatalf("claims %v", c)
	}
	p := c["static_call_path_found"][0]
	if p.VulnID != "SYNTH-0001" || p.Status != "supported" || len(p.EvidenceIDs) != 2 || !strings.HasSuffix(p.EvidenceIDs[1], ".scope") {
		t.Fatalf("static claim must cite the path and the scope: %+v", p)
	}
}

func TestVulnPackageAndModuleOnlyNeverBecomeACallPath(t *testing.T) { // U7
	st, err := parseVulnStream(readTestdata(t, "SYNTHETIC_findings.json"))
	if err != nil {
		t.Fatal(err)
	}
	var kept []vulnFinding
	for _, f := range st.Findings {
		if findingLevel(f) != "symbol" {
			kept = append(kept, f)
		}
	}
	st.Findings = kept
	res := &Result{Evidence: []EvidenceItem{}, Claims: []Claim{}}
	buildVulnEvidence(res, vulnTask(), st, ArtifactRef{Digest: "sha256:" + strings.Repeat("b", 64)}, "sha256:"+strings.Repeat("c", 64),
		"db", "t", "v", "linux", "amd64")
	k := kinds(res)
	if k["vuln_call_path"] != 0 || k["vuln_package_imported"] != 1 || k["vuln_module_required"] != 1 {
		t.Fatalf("kinds %v", k)
	}
	c := claimsByType(res)
	if len(c["static_call_path_found"]) != 0 {
		t.Fatal("package/module-level evidence produced a call-path claim")
	}
	np := c["call_path_not_established"]
	if len(np) != 1 || np[0].Status != "unknown" || len(np[0].EvidenceIDs) != 1 || !strings.Contains(np[0].Explanation, "not evidence of absence") {
		t.Fatalf("not-established claim: %+v", np)
	}
	if len(c["vulnerable_package_imported"]) != 1 {
		t.Fatalf("package claim missing: %v", c)
	}
}

func TestVulnAnalyzerFailureFamily(t *testing.T) { // U6
	full := readTestdata(t, "SYNTHETIC_findings.json")
	cases := []struct {
		name string
		data []byte
		exit int
	}{
		{"truncated mid-message", full[:len(full)/2], 0},
		{"missing config", []byte(`{"progress":{"message":"` + finalProgress + `"}}`), 0},
		{"non-zero exit with a full stream", full, 1},
		{"stream ended before the analysis", []byte(`{"config":{"protocol_version":"v1.0.0","scan_mode":"source","scanner_version":"v1.1.4"}}`), 0},
		{"toolchain failure stream", readTestdata(t, "SYNTHETIC_toolchain_failure_stream.json"), 1},
		{"toolchain failure stream even at exit 0", readTestdata(t, "SYNTHETIC_toolchain_failure_stream.json"), 0},
		{"binary mode", []byte(strings.Replace(string(full), `"scan_mode": "source"`, `"scan_mode": "binary"`, 1)), 0},
		{"unknown protocol", []byte(strings.Replace(string(full), `"v1.0.0"`, `"v2.0.0"`, 1)), 0},
		{"empty output", nil, 0},
	}
	for _, tc := range cases {
		st, err := parseVulnStream(tc.data)
		if streamComplete(st, err, tc.exit) == nil {
			t.Errorf("%s: treated as a complete analysis", tc.name)
		}
	}
	st, err := parseVulnStream(full)
	if e := streamComplete(st, err, 0); e != nil {
		t.Fatalf("a full stream with exit 0 must be complete: %v", e)
	}
}

func TestVulnExitZeroWithFindingsIsStillJustAStream(t *testing.T) {
	// findings do not change the exit status in JSON mode; completeness never depends on them.
	st, err := parseVulnStream(readTestdata(t, "SYNTHETIC_findings.json"))
	if err != nil || len(st.Findings) != 3 || streamComplete(st, err, 0) != nil {
		t.Fatalf("findings=%d err=%v", len(st.Findings), err)
	}
}

func TestVulnMalformedFindingIsAnError(t *testing.T) {
	_, err := parseVulnStream([]byte(`{"finding":{"osv":"X"}}`))
	if err == nil {
		t.Fatal("a finding without a trace must be an error")
	}
}

// Contract 1.0.2: the analyzer pattern, the recorded argv, the scope metadata and the scope wording agree.
func TestScopeRecordsTheProgramMainPattern(t *testing.T) {
	res, _ := buildFrom(t, readTestdata(t, "SYNTHETIC_findings.json"))
	found := false
	for _, e := range res.Evidence {
		if e.Kind != "govulncheck_scope" {
			continue
		}
		found = true
		if govulncheckPattern != "./cmd/..." {
			t.Fatalf("pattern %q", govulncheckPattern)
		}
		d := e.Details.(map[string]any)
		pats := d["analyzed_patterns"].([]string)
		if len(pats) != 1 || pats[0] != "./cmd/..." {
			t.Fatalf("analyzed_patterns %v", pats)
		}
		argv := e.CollectionMethod.ArgvTemplate
		if argv[len(argv)-1] != "./cmd/..." {
			t.Fatalf("argv %v", argv)
		}
		if !strings.Contains(e.Scope, "program main package") || !strings.Contains(e.Scope, "Exported library API entry points are not analyzed independently") {
			t.Fatalf("scope wording %q", e.Scope)
		}
	}
	if !found {
		t.Fatal("no govulncheck_scope evidence")
	}
}
