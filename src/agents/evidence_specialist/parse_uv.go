package main

// uv.lock (version 1) reader (I3-REQ-04). A TOML subset reader for the generated format: it relies only on the
// top-level `version`, each [[package]] table's `name`, `version`, `source` and the names inside `dependencies`,
// `[package.optional-dependencies]` and `[package.dev-dependencies]`. Other tables and keys are skipped by
// header or by balanced-value scanning without interpretation; a malformed skipped region is counted.

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

type tomlVal struct {
	str    string
	isStr  bool
	arr    []tomlVal
	isArr  bool
	tbl    map[string]tomlVal
	isTbl  bool
	raw    string
	number bool
}

type tomlScanner struct {
	s   string
	pos int
}

func (t *tomlScanner) skipWS(newlines bool) {
	for t.pos < len(t.s) {
		c := t.s[t.pos]
		if c == ' ' || c == '\t' || c == '\r' || (newlines && c == '\n') {
			t.pos++
		} else if c == '#' && newlines {
			for t.pos < len(t.s) && t.s[t.pos] != '\n' {
				t.pos++
			}
		} else {
			break
		}
	}
}

func (t *tomlScanner) value() (tomlVal, error) {
	t.skipWS(false)
	if t.pos >= len(t.s) {
		return tomlVal{}, fmt.Errorf("value expected")
	}
	switch c := t.s[t.pos]; {
	case c == '"':
		return t.basicString()
	case c == '\'':
		end := strings.IndexByte(t.s[t.pos+1:], '\'')
		nl := strings.IndexByte(t.s[t.pos+1:], '\n')
		if end < 0 || (nl >= 0 && nl < end) {
			return tomlVal{}, fmt.Errorf("unterminated literal string")
		}
		v := t.s[t.pos+1 : t.pos+1+end]
		t.pos += end + 2
		return tomlVal{str: v, isStr: true}, nil
	case c == '[':
		return t.array()
	case c == '{':
		return t.inlineTable()
	default:
		start := t.pos
		for t.pos < len(t.s) && !strings.ContainsRune(",]}\n# \t\r", rune(t.s[t.pos])) {
			t.pos++
		}
		raw := t.s[start:t.pos]
		if raw == "" {
			return tomlVal{}, fmt.Errorf("empty value")
		}
		if raw == "true" || raw == "false" {
			return tomlVal{raw: raw}, nil
		}
		if _, err := strconv.ParseInt(strings.ReplaceAll(raw, "_", ""), 0, 64); err == nil {
			return tomlVal{raw: raw, number: true}, nil
		}
		if _, err := strconv.ParseFloat(strings.ReplaceAll(raw, "_", ""), 64); err == nil {
			return tomlVal{raw: raw, number: true}, nil
		}
		return tomlVal{}, fmt.Errorf("unsupported scalar %q", raw)
	}
}

func (t *tomlScanner) basicString() (tomlVal, error) {
	if strings.HasPrefix(t.s[t.pos:], `"""`) {
		return tomlVal{}, fmt.Errorf("multi-line strings are not supported")
	}
	i := t.pos + 1
	for i < len(t.s) {
		switch t.s[i] {
		case '\\':
			i += 2
			continue
		case '\n':
			return tomlVal{}, fmt.Errorf("unterminated string")
		case '"':
			q, err := strconv.Unquote(t.s[t.pos : i+1])
			if err != nil {
				return tomlVal{}, fmt.Errorf("bad string escape")
			}
			t.pos = i + 1
			return tomlVal{str: q, isStr: true}, nil
		}
		i++
	}
	return tomlVal{}, fmt.Errorf("unterminated string")
}

func (t *tomlScanner) array() (tomlVal, error) {
	t.pos++
	out := tomlVal{isArr: true}
	for {
		t.skipWS(true)
		if t.pos >= len(t.s) {
			return tomlVal{}, fmt.Errorf("unterminated array")
		}
		if t.s[t.pos] == ']' {
			t.pos++
			return out, nil
		}
		v, err := t.value()
		if err != nil {
			return tomlVal{}, err
		}
		out.arr = append(out.arr, v)
		if len(out.arr) > maxRows*4 {
			return tomlVal{}, fmt.Errorf("array too long")
		}
		t.skipWS(true)
		if t.pos < len(t.s) && t.s[t.pos] == ',' {
			t.pos++
		}
	}
}

func (t *tomlScanner) inlineTable() (tomlVal, error) {
	t.pos++
	out := tomlVal{isTbl: true, tbl: map[string]tomlVal{}}
	for {
		t.skipWS(true)
		if t.pos >= len(t.s) {
			return tomlVal{}, fmt.Errorf("unterminated inline table")
		}
		if t.s[t.pos] == '}' {
			t.pos++
			return out, nil
		}
		key, err := t.key()
		if err != nil {
			return tomlVal{}, err
		}
		t.skipWS(false)
		if t.pos >= len(t.s) || t.s[t.pos] != '=' {
			return tomlVal{}, fmt.Errorf("= expected")
		}
		t.pos++
		v, err := t.value()
		if err != nil {
			return tomlVal{}, err
		}
		out.tbl[key] = v
		t.skipWS(true)
		if t.pos < len(t.s) && t.s[t.pos] == ',' {
			t.pos++
		}
	}
}

func (t *tomlScanner) key() (string, error) {
	t.skipWS(false)
	if t.pos < len(t.s) && t.s[t.pos] == '"' {
		v, err := t.basicString()
		return v.str, err
	}
	start := t.pos
	for t.pos < len(t.s) {
		c := t.s[t.pos]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' {
			t.pos++
		} else {
			break
		}
	}
	if start == t.pos {
		return "", fmt.Errorf("key expected")
	}
	return t.s[start:t.pos], nil
}

// skipValue advances over one value without interpreting it: balanced brackets/braces and quoted strings.
func (t *tomlScanner) skipValue() error {
	t.skipWS(false)
	depth := 0
	for t.pos < len(t.s) {
		c := t.s[t.pos]
		switch {
		case c == '"' || c == '\'':
			quote := c
			t.pos++
			for t.pos < len(t.s) && t.s[t.pos] != quote && t.s[t.pos] != '\n' {
				if quote == '"' && t.s[t.pos] == '\\' {
					t.pos++
				}
				t.pos++
			}
			if t.pos >= len(t.s) || t.s[t.pos] != quote {
				return fmt.Errorf("unterminated string in a skipped region")
			}
			t.pos++
		case c == '[' || c == '{':
			depth++
			t.pos++
		case c == ']' || c == '}':
			depth--
			t.pos++
		case c == '#':
			for t.pos < len(t.s) && t.s[t.pos] != '\n' {
				t.pos++
			}
		case c == '\n':
			if depth <= 0 {
				return nil
			}
			t.pos++
		default:
			t.pos++
		}
		if depth < 0 {
			return fmt.Errorf("unbalanced bracket in a skipped region")
		}
	}
	if depth != 0 {
		return fmt.Errorf("unterminated array or table in a skipped region")
	}
	return nil
}

type uvPackage struct {
	name, version string
	hasVersion    bool
	sourceKind    string
	sourceValue   string
	deps          []string
	opt, dev      []string
	ok            bool
}

func tomlDepNames(v tomlVal) ([]string, bool) {
	if !v.isArr {
		return nil, false
	}
	var out []string
	for _, e := range v.arr {
		if !e.isTbl {
			return nil, false
		}
		n, ok := e.tbl["name"]
		if !ok || !n.isStr {
			return nil, false
		}
		out = append(out, n.str)
	}
	return out, true
}

func parseUvLock(data []byte) *parseResult {
	res := newParseResult()
	if len(data) > maxManifestBytes {
		return res.fail("too_large", "lock file exceeds the size limit")
	}
	text := string(data)
	if strings.Count(text, "\n") > maxLines {
		return res.fail("malformed", "too many lines")
	}
	sc := &tomlScanner{s: text}
	var pkgs []*uvPackage
	var cur *uvPackage
	table := "" // current table path: "", "package", "package.optional-dependencies", "package.dev-dependencies", other
	topVersion := ""
	haveTop := false
	for sc.pos < len(sc.s) {
		sc.skipWS(true)
		if sc.pos >= len(sc.s) {
			break
		}
		c := sc.s[sc.pos]
		if c == '[' {
			end := strings.IndexByte(sc.s[sc.pos:], '\n')
			if end < 0 {
				end = len(sc.s) - sc.pos
			}
			header := strings.TrimSpace(sc.s[sc.pos : sc.pos+end])
			if i := strings.Index(header, "#"); i >= 0 {
				header = strings.TrimSpace(header[:i])
			}
			sc.pos += end
			switch header {
			case "[[package]]":
				cur = &uvPackage{ok: true}
				pkgs = append(pkgs, cur)
				table = "package"
			case "[package.optional-dependencies]":
				table = "package.optional-dependencies"
			case "[package.dev-dependencies]":
				table = "package.dev-dependencies"
			default:
				if !strings.HasPrefix(header, "[") || !strings.HasSuffix(header, "]") {
					res.unparsed("table_header")
				}
				table = "other"
			}
			continue
		}
		key, err := sc.key()
		if err != nil {
			res.unparsed("key_line")
			for sc.pos < len(sc.s) && sc.s[sc.pos] != '\n' {
				sc.pos++
			}
			continue
		}
		sc.skipWS(false)
		if sc.pos >= len(sc.s) || sc.s[sc.pos] != '=' {
			res.unparsed("key_without_value")
			for sc.pos < len(sc.s) && sc.s[sc.pos] != '\n' {
				sc.pos++
			}
			continue
		}
		sc.pos++
		relied := false
		switch {
		case table == "" && key == "version":
			relied = true
		case table == "package" && cur != nil && (key == "name" || key == "version" || key == "source" || key == "dependencies"):
			relied = true
		case table == "package.optional-dependencies" || table == "package.dev-dependencies":
			relied = cur != nil
		}
		if !relied {
			if err := sc.skipValue(); err != nil {
				res.unparsed("skipped_region_malformed")
				for sc.pos < len(sc.s) && sc.s[sc.pos] != '\n' {
					sc.pos++
				}
			}
			continue
		}
		start := sc.pos
		v, err := sc.value()
		if err != nil {
			res.unparsed("relied_field_" + strings.ReplaceAll(strings.ReplaceAll(table, ".", "_"), "-", "_") + "_" + key)
			sc.pos = start
			if err := sc.skipValue(); err != nil {
				for sc.pos < len(sc.s) && sc.s[sc.pos] != '\n' {
					sc.pos++
				}
			}
			if table == "package" && cur != nil {
				cur.ok = false
			}
			continue
		}
		switch {
		case table == "":
			topVersion, haveTop = v.raw, v.number
		case table == "package":
			switch key {
			case "name":
				if v.isStr {
					cur.name = v.str
				} else {
					res.unparsed("package_name")
					cur.ok = false
				}
			case "version":
				if v.isStr {
					cur.version, cur.hasVersion = v.str, true
				} else {
					res.unparsed("package_version")
					cur.ok = false
				}
			case "source":
				if v.isTbl && len(v.tbl) == 1 {
					for k, tv := range v.tbl {
						cur.sourceKind = k
						if tv.isStr {
							cur.sourceValue = tv.str
						}
					}
				} else {
					res.unparsed("package_source")
					cur.ok = false
				}
			case "dependencies":
				names, ok := tomlDepNames(v)
				if !ok {
					res.unparsed("dependencies_entries")
					cur.ok = false
				}
				cur.deps = names
			}
		default:
			names, ok := tomlDepNames(v)
			if !ok {
				res.unparsed("group_dependencies_entries")
				continue
			}
			if table == "package.optional-dependencies" {
				cur.opt = append(cur.opt, names...)
			} else {
				cur.dev = append(cur.dev, names...)
			}
		}
	}
	if !haveTop {
		return res.fail("malformed", "no top-level version")
	}
	res.FormatVersion = strp(topVersion)
	if topVersion != "1" {
		return res.fail("unsupported", "uv.lock version "+topVersion+" is not 1")
	}
	// workspace members and the dependency scopes they declare
	scopes := map[string]map[string]bool{}
	add := func(names []string, scope string) {
		for _, n := range names {
			k := pep503(n)
			if scopes[k] == nil {
				scopes[k] = map[string]bool{}
			}
			scopes[k][scope] = true
		}
	}
	for _, p := range pkgs {
		if p.sourceKind == "editable" || p.sourceKind == "virtual" {
			add(p.deps, "runtime")
			add(p.opt, "optional")
			add(p.dev, "dev")
		}
	}
	for i, p := range pkgs {
		if !p.ok || p.name == "" {
			res.unparsed("package_block")
			continue
		}
		if !validIdentity("PyPI", p.name) {
			res.unparsed("rejected_name")
			continue
		}
		row := occRow{Locator: "/package/" + strconv.Itoa(i), Ecosystem: "PyPI", NameOriginal: p.name, NameNormalized: pep503(p.name),
			Scope: "unknown", ScopeBasis: "not_derived_transitive", SourceKind: "uv_" + p.sourceKind}
		if p.hasVersion {
			if !validText(p.version, maxVersionBytes) {
				res.unparsed("rejected_version")
				continue
			}
			row.VersionOriginal = strp(p.version)
		}
		switch p.sourceKind {
		case "editable", "virtual":
			row.VersionState, row.Direct = "workspace", nil
			if d, ok := relDir(p.sourceValue); ok {
				res.CoveredDirs = append(res.CoveredDirs, d) // member directory, relative to the lock's directory
			}
		case "registry":
			if p.hasVersion {
				row.VersionState = "exact"
			} else {
				row.VersionState = "missing"
			}
		default:
			row.VersionState = "non_registry"
		}
		if p.sourceKind != "editable" && p.sourceKind != "virtual" {
			row.Direct = boolp(false)
			if sc := scopes[row.NameNormalized]; sc != nil {
				row.Direct = boolp(true)
				for _, s := range []string{"runtime", "optional", "dev"} {
					if sc[s] {
						row.Scope, row.ScopeBasis = s, "workspace_dependency_table"
						break
					}
				}
			}
		}
		res.Rows = append(res.Rows, row)
	}
	finishRows(res)
	sort.Strings(res.CoveredDirs)
	return res
}
