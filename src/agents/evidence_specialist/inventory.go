package main

// I3 occurrence tables, row types and the shared limits of the static manifest parsers (I3-REQ-04).
// Every parser here reads untrusted bytes: it has fixed size, depth and row limits, terminates on input
// length, and reports anything it does not understand as a counted unparsed construct. Nothing here
// executes cohort code or runs a subprocess.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

const (
	parserVersion     = "i3/1"
	maxJSONDepth      = 64
	maxLines          = 200000
	maxRows           = 20000
	maxTableBytes     = 1 << 20
	maxNameBytes      = 512
	maxVersionBytes   = 128
	maxManifestBytes  = 4 << 20
	tableSchemaOcc    = "opentrace.occurrence_table/1"
	tableSchemaHosted = "opentrace.hosted_table/1"
)

// occRow is one package occurrence. VersionOriginal and Direct may be null (JSON null).
type occRow struct {
	Locator           string  `json:"locator"`
	Ecosystem         string  `json:"ecosystem"`
	NameOriginal      string  `json:"name_original"`
	NameNormalized    string  `json:"name_normalized"`
	VersionOriginal   *string `json:"version_original"`
	VersionState      string  `json:"version_state"`
	Direct            *bool   `json:"direct"`
	Scope             string  `json:"scope"`
	ScopeBasis        string  `json:"scope_basis"`
	IntegrityRecorded *bool   `json:"integrity_recorded"`
	SourceKind        string  `json:"source_kind"`
	InstalledName     string  `json:"installed_name,omitempty"`
	Alias             *bool   `json:"alias,omitempty"`
	ReplacedBy        string  `json:"replaced_by,omitempty"`
}

// parseResult is the outcome of one manifest parse.
type parseResult struct {
	Rows          []occRow
	Unparsed      map[string]int // construct class -> count
	FormatVersion *string
	Status        string // parsed | partial | malformed | unsupported
	Reason        string
	CoveredDirs   []string // directories whose package.json/pyproject are covered by this lock
}

func newParseResult() *parseResult { return &parseResult{Unparsed: map[string]int{}, Status: "parsed"} }

func (p *parseResult) unparsed(class string) {
	p.Unparsed[class]++
	if p.Status == "parsed" {
		p.Status = "partial"
	}
}

func (p *parseResult) fail(status, reason string) *parseResult {
	p.Status, p.Reason = status, reason
	return p
}

func (p *parseResult) unparsedList() []map[string]any {
	out := []map[string]any{}
	keys := make([]string, 0, len(p.Unparsed))
	for k := range p.Unparsed {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		out = append(out, map[string]any{"class": k, "count": p.Unparsed[k]})
	}
	return out
}

func strp(s string) *string { return &s }
func boolp(b bool) *bool    { return &b }

var (
	pepRunRE   = regexp.MustCompile(`[-_.]+`)
	goPathRE   = regexp.MustCompile(`^[A-Za-z0-9._~/+:-]+$`)
	npmNameRE  = regexp.MustCompile(`^(@[A-Za-z0-9._~-]+/)?[A-Za-z0-9._~-]+$`)
	pypiNameRE = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$`)
)

func pep503(name string) string { return strings.ToLower(pepRunRE.ReplaceAllString(name, "-")) }

// validText rejects control characters, invalid UTF-8 and over-long strings.
func validText(s string, max int) bool {
	if len(s) > max || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func validIdentity(eco, name string) bool {
	if !validText(name, maxNameBytes) || name == "" {
		return false
	}
	switch eco {
	case "Go":
		return goPathRE.MatchString(name) && goElementsOK(name)
	case "npm":
		return len(name) <= 214 && npmNameRE.MatchString(name)
	case "PyPI":
		return pypiNameRE.MatchString(name)
	}
	return false
}

// finishRows sorts bytewise by locator, enforces the row cap and returns the canonical table bytes.
func finishRows(res *parseResult) {
	sort.SliceStable(res.Rows, func(i, j int) bool { return res.Rows[i].Locator < res.Rows[j].Locator })
	if len(res.Rows) > maxRows {
		res.Rows = res.Rows[:maxRows]
		res.unparsed("output_limit_rows")
	}
}

// canonicalAny marshals v with sorted object keys, no HTML escaping and one trailing LF, so table
// bytes are deterministic (the same rule the core uses for its manifests).
func canonicalAny(v any) ([]byte, error) {
	raw, err := marshalNoEscape(v)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var generic any
	if err := dec.Decode(&generic); err != nil {
		return nil, err
	}
	out, err := marshalNoEscape(generic)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func marshalNoEscape(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil { // Encode appends exactly one LF
		return nil, err
	}
	return buf.Bytes(), nil
}

type occTable struct {
	Schema string   `json:"schema"`
	Repo   string   `json:"repo"`
	Commit string   `json:"commit"`
	Path   string   `json:"path"`
	Kind   string   `json:"kind"`
	Rows   []occRow `json:"rows"`
}

func buildOccTable(repo, commit, path, kind string, rows []occRow) ([]byte, error) {
	if rows == nil {
		rows = []occRow{}
	}
	data, err := canonicalAny(occTable{Schema: tableSchemaOcc, Repo: repo, Commit: commit, Path: path, Kind: kind, Rows: rows})
	if err != nil {
		return nil, err
	}
	if len(data) > maxTableBytes {
		return nil, fmt.Errorf("output_limit")
	}
	return data, nil
}

// jsonDepthOK scans for nesting deeper than max without recursion on untrusted structure.
func jsonDepthOK(data []byte, max int) bool {
	depth, inStr, esc := 0, false, false
	for _, b := range data {
		if inStr {
			switch {
			case esc:
				esc = false
			case b == '\\':
				esc = true
			case b == '"':
				inStr = false
			}
			continue
		}
		switch b {
		case '"':
			inStr = true
		case '{', '[':
			depth++
			if depth > max {
				return false
			}
		case '}', ']':
			depth--
		}
	}
	return true
}

// lineScanner yields logical lines of at most maxLines, tracking the line number (1-based).
func splitLines(data []byte) ([]string, bool) {
	text := string(data)
	lines := strings.Split(text, "\n")
	if len(lines) > maxLines {
		return nil, false
	}
	for i, l := range lines {
		lines[i] = strings.TrimSuffix(l, "\r")
	}
	return lines, true
}

// relDir normalizes a directory written in a lock file ("." for the lock's own directory) to a clean
// slash-separated path relative to it; paths that are absolute or climb out are rejected.
func relDir(p string) (string, bool) {
	if p == "" || p == "." {
		return "", true
	}
	if strings.HasPrefix(p, "/") || strings.Contains(p, "\\") || !validText(p, 512) {
		return "", false
	}
	var parts []string
	for _, seg := range strings.Split(p, "/") {
		switch seg {
		case "", ".":
		case "..":
			return "", false
		default:
			parts = append(parts, seg)
		}
	}
	return strings.Join(parts, "/"), true
}

// goElementsOK applies the module-path element rule: no empty element and no element that begins or ends with a
// dot, which also rejects "." and ".." segments (a module path is never a filesystem path here, but it is never
// accepted as a query component in that shape either).
func goElementsOK(name string) bool {
	for _, el := range strings.Split(name, "/") {
		if el == "" || strings.HasPrefix(el, ".") || strings.HasSuffix(el, ".") {
			return false
		}
	}
	return true
}
