package main

// govulncheck_source stream interpretation (I2-REQ-06). Pure parsing and evidence building; the
// sandboxed execution lives in vulnrun.go. Exit status zero is not "no vulnerabilities" and the
// JSON mode does not change the exit status for findings, so completeness is judged from the
// stream itself plus the exit status and stderr supplied by the runner.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

const finalProgress = "Checking the code against the vulnerabilities..."

type vulnFrame struct {
	Module   string `json:"module"`
	Version  string `json:"version"`
	Package  string `json:"package"`
	Function string `json:"function"`
	Receiver string `json:"receiver"`
	Position *struct {
		Filename string `json:"filename"`
		Offset   int    `json:"offset"`
		Line     int    `json:"line"`
		Column   int    `json:"column"`
	} `json:"position"`
}

type vulnFinding struct {
	OSV          string      `json:"osv"`
	FixedVersion string      `json:"fixed_version"`
	Trace        []vulnFrame `json:"trace"`
}

type vulnConfig struct {
	ProtocolVersion string `json:"protocol_version"`
	ScannerName     string `json:"scanner_name"`
	ScannerVersion  string `json:"scanner_version"`
	DB              string `json:"db"`
	DBLastModified  string `json:"db_last_modified"`
	GoVersion       string `json:"go_version"`
	ScanLevel       string `json:"scan_level"`
	ScanMode        string `json:"scan_mode"`
}

type vulnStream struct {
	Config       *vulnConfig
	MainModule   string
	OSVIDs       []string
	Findings     []vulnFinding
	SawFinal     bool
	MessageCount int
}

// parseVulnStream decodes the concatenated JSON messages. A syntax error is a truncated or corrupt
// stream. It never guesses: the caller decides completeness with streamComplete.
func parseVulnStream(data []byte) (*vulnStream, error) {
	st := &vulnStream{}
	dec := json.NewDecoder(bytes.NewReader(data))
	seen := map[string]bool{}
	for {
		var msg map[string]json.RawMessage
		err := dec.Decode(&msg)
		if err == io.EOF {
			break
		}
		if err != nil {
			return st, fmt.Errorf("stream is truncated or malformed after %d messages: %v", st.MessageCount, err)
		}
		st.MessageCount++
		for key, raw := range msg {
			switch key {
			case "config":
				var c vulnConfig
				if json.Unmarshal(raw, &c) != nil {
					return st, errors.New("config message is malformed")
				}
				st.Config = &c
			case "SBOM":
				var sbom struct {
					Modules []struct {
						Path    string `json:"path"`
						Version string `json:"version"`
					} `json:"modules"`
				}
				if json.Unmarshal(raw, &sbom) == nil {
					for _, m := range sbom.Modules {
						if m.Version == "" && m.Path != "" && st.MainModule == "" {
							st.MainModule = m.Path
						}
					}
				}
			case "progress":
				var p struct {
					Message string `json:"message"`
				}
				if json.Unmarshal(raw, &p) == nil && p.Message == finalProgress {
					st.SawFinal = true
				}
			case "osv":
				var o struct {
					ID string `json:"id"`
				}
				if json.Unmarshal(raw, &o) == nil && o.ID != "" && !seen[o.ID] {
					seen[o.ID] = true
					st.OSVIDs = append(st.OSVIDs, o.ID)
				}
			case "finding":
				var f vulnFinding
				if json.Unmarshal(raw, &f) != nil || f.OSV == "" || len(f.Trace) == 0 {
					return st, errors.New("finding message is malformed")
				}
				st.Findings = append(st.Findings, f)
			}
		}
	}
	return st, nil
}

// streamComplete says whether the analyzer finished: clean decode (the error from parseVulnStream
// is nil), a config message, source mode, the final progress message and exit status zero.
func streamComplete(st *vulnStream, parseErr error, exitCode int) error {
	switch {
	case parseErr != nil:
		return parseErr
	case exitCode != 0:
		return fmt.Errorf("govulncheck exited with status %d", exitCode)
	case st.Config == nil:
		return errors.New("no config message in the stream")
	case st.Config.ScanMode != "source":
		return fmt.Errorf("scan mode %q is not source", st.Config.ScanMode)
	case !strings.HasPrefix(st.Config.ProtocolVersion, "v1."):
		return fmt.Errorf("unsupported protocol version %q", st.Config.ProtocolVersion)
	case !st.SawFinal:
		return errors.New("the stream ended before the analysis completed")
	}
	return nil
}

func findingLevel(f vulnFinding) string {
	last := f.Trace[len(f.Trace)-1]
	first := f.Trace[0]
	switch {
	case first.Function != "":
		return "symbol"
	case first.Package != "" || last.Package != "":
		return "package"
	}
	return "module"
}

type vulnItem struct {
	Level        string
	OSV          string
	Module       string
	Version      string
	FixedVersion string
	Trace        []map[string]any // entry first
	Raw          vulnFinding
}

func (st *vulnStream) items() []vulnItem {
	var out []vulnItem
	for _, f := range st.Findings {
		it := vulnItem{Level: findingLevel(f), OSV: f.OSV, Module: f.Trace[0].Module, Version: f.Trace[0].Version,
			FixedVersion: strings.TrimPrefix(f.FixedVersion, "v"), Raw: f}
		if it.Level == "symbol" {
			// govulncheck lists the vulnerable symbol first and the caller last; the contract is entry first.
			for i := len(f.Trace) - 1; i >= 0; i-- {
				fr := f.Trace[i]
				pos := map[string]any{"file": "", "line": 0, "column": 0}
				if fr.Position != nil {
					pos = map[string]any{"file": fr.Position.Filename, "line": fr.Position.Line, "column": fr.Position.Column}
				}
				var recv, ver any
				if fr.Receiver != "" {
					recv = fr.Receiver
				}
				if fr.Version != "" {
					ver = fr.Version
				}
				it.Trace = append(it.Trace, map[string]any{"module": fr.Module, "version": ver, "package": fr.Package,
					"function": fr.Function, "receiver": recv, "position": pos})
			}
		}
		out = append(out, it)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].OSV != out[j].OSV {
			return out[i].OSV < out[j].OSV
		}
		return out[i].Level < out[j].Level
	})
	return out
}

const maxPathsPerVuln = 20

// govulncheckPattern is the package pattern given to govulncheck (contract 1.0.2, section 3.6).
// Analysis starts at the fixture's program main package(s); exported library API entry points are
// not analyzed independently.
const govulncheckPattern = "./cmd/..."

// buildVulnEvidence turns a complete stream into evidence and claims. scopeEnv carries the
// analysis configuration; artifactDigest is the stored normalized stream.
func buildVulnEvidence(res *Result, t *TaskRequest, st *vulnStream, inputRef ArtifactRef, artifactDigest, dbURL, stamp, toolVersion string, goos, goarch string) {
	method := CollectionMethod{Tool: "govulncheck", ToolVersion: toolVersion,
		ArgvTemplate: []string{"govulncheck", "-mode=source", "-format=json", "-db", "<capture-db>", govulncheckPattern}, OutputArtifact: artifactDigest}
	main := st.MainModule
	scopeID := t.TaskID + ".scope"
	res.Evidence = append(res.Evidence, EvidenceItem{EvidenceID: scopeID, Dimension: "call_path", Kind: "govulncheck_scope",
		Subject: Subject{Module: main, Version: t.Context.RequestedRevision, Indirect: false}, ArtifactRef: inputRef,
		Locator: "govulncheck#config", Observation: "govulncheck completed a source analysis of " + govulncheckPattern + " under the recorded build assumptions.",
		CollectionMethod: method,
		Scope:            "Static analysis starting at the fixture program main package(s) (" + govulncheckPattern + ", including the library code they import) for the recorded GOOS/GOARCH, no build tags, against the captured vulnerability database. Exported library API entry points are not analyzed independently.",
		Limitations: []string{"Static calls within the analyzed build scope only; no proof of a runtime trigger or of absence outside the analyzed paths.",
			"Reflection, unsafe and conservative interface or function-pointer treatment limit conclusions."},
		ObservedAt: stamp,
		Details: map[string]any{"scan_mode": "source", "scanner_version": st.Config.ScannerName + "@" + st.Config.ScannerVersion,
			"go_version": st.Config.GoVersion, "goos": goos, "goarch": goarch, "cgo": false, "build_tags": []string{},
			"db_url": dbURL, "db_last_modified": nilIfEmpty(st.Config.DBLastModified), "analyzed_patterns": []string{govulncheckPattern},
			"main_module": main, "stream_complete": true}})

	ids := append([]string{}, st.OSVIDs...)
	known := map[string]bool{}
	for _, id := range ids {
		known[id] = true
	}
	items := st.items()
	for _, it := range items {
		if !known[it.OSV] {
			known[it.OSV] = true
			ids = append(ids, it.OSV)
		}
	}
	sort.Strings(ids)
	pathEv := map[string][]string{}
	pkgEv := map[string][]string{}
	counts := map[string]int{}
	n := 0
	for _, it := range items {
		n++
		base := map[string]any{"vuln_id": it.OSV, "level": it.Level, "module": it.Module, "version": nilIfEmpty(it.Version),
			"fixed_version": nilIfEmpty(it.FixedVersion)}
		id := fmt.Sprintf("%s.f%d", t.TaskID, n)
		ev := EvidenceItem{EvidenceID: id, Observation: fmt.Sprintf("govulncheck reported a %s-level finding for %s in %s.", it.Level, it.OSV, it.Module),
			Subject: Subject{Module: it.Module, Version: it.Version}, ArtifactRef: inputRef, CollectionMethod: method,
			Locator: "govulncheck#" + it.OSV + "#" + it.Level, ObservedAt: stamp}
		switch it.Level {
		case "module":
			ev.Dimension, ev.Kind = "inventory", "vuln_module_required"
			ev.Scope = "The module is required by the build; the analyzer reports no imported package or call."
			ev.Limitations = []string{"Module-level only: not evidence of an imported package or a call."}
			ev.Details = base
		case "package":
			ev.Dimension, ev.Kind = "code_presence", "vuln_package_imported"
			ev.Scope = "A package containing a vulnerable symbol is imported; the analyzer found no call to it."
			ev.Limitations = []string{"Package-level only: not evidence of a call path."}
			ev.Details = base
			pkgEv[it.OSV] = append(pkgEv[it.OSV], id)
		default:
			if counts[it.OSV] >= maxPathsPerVuln {
				n--
				continue
			}
			counts[it.OSV]++
			ev.Dimension, ev.Kind = "call_path", "vuln_call_path"
			ev.Scope = "A static call path found under the named build assumptions."
			ev.Limitations = []string{"A static path is not a runtime trigger or exploit observation."}
			base["trace"] = it.Trace
			ev.Details = base
			pathEv[it.OSV] = append(pathEv[it.OSV], id)
		}
		res.Evidence = append(res.Evidence, ev)
	}
	c := 0
	for _, id := range ids {
		c++
		if paths := pathEv[id]; len(paths) > 0 {
			res.Claims = append(res.Claims, Claim{ClaimID: fmt.Sprintf("%s.cp%d", t.TaskID, c), Type: "static_call_path_found",
				Dimension: "call_path", Proposition: fmt.Sprintf("govulncheck found a static call path to a vulnerable symbol of %s under the recorded build assumptions.", id),
				EvidenceIDs: append(append([]string{}, paths...), scopeID), Status: "supported", VulnID: id,
				Explanation: "Supported by the call-path evidence and the analysis scope; a static path is not a runtime trigger."})
		} else {
			res.Claims = append(res.Claims, Claim{ClaimID: fmt.Sprintf("%s.np%d", t.TaskID, c), Type: "call_path_not_established",
				Dimension: "call_path", Proposition: fmt.Sprintf("No call path to %s was established under these build assumptions.", id),
				EvidenceIDs: []string{scopeID}, Status: "unknown", VulnID: id,
				Explanation: "The analysis completed without a path for this advisory; that is not evidence of absence, safety or non-exploitability."})
		}
		if pk := pkgEv[id]; len(pk) > 0 {
			res.Claims = append(res.Claims, Claim{ClaimID: fmt.Sprintf("%s.pk%d", t.TaskID, c), Type: "vulnerable_package_imported",
				Dimension: "code_presence", Proposition: fmt.Sprintf("A package containing a vulnerable symbol of %s is imported.", id),
				EvidenceIDs: pk, Status: "supported", VulnID: id,
				Explanation: "Package-level finding only; it does not establish a call."})
		}
	}
}

func nilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
