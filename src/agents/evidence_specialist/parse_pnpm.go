package main

// pnpm-lock.yaml (lockfileVersion 9.x) reader (I3-REQ-04). A constrained, indentation-based reader for the
// generated format: it relies only on lockfileVersion, importers.<path>.{dependencies,devDependencies,
// optionalDependencies}.<name>.{specifier,version} and the keys of `packages`. Every other section and every
// deeper line is skipped by indentation without interpretation. An unsupported construct inside a relied-on
// field (tab indentation, unterminated quote, anchors, multi-line scalars, a key it cannot read) is counted
// and prevents `parsed`.

import (
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

type yline struct {
	no     int
	indent int
	key    string
	value  string // raw value text after "key:", trimmed, comment removed; "" when absent
	ok     bool
}

// readYAMLKey parses `key:` at the start of s (after indentation). Plain keys end at ": " or a trailing ':'.
func readYAMLKey(s string) (key, rest string, ok bool) {
	if s == "" {
		return "", "", false
	}
	switch s[0] {
	case '\'':
		var b strings.Builder
		i := 1
		for i < len(s) {
			if s[i] == '\'' {
				if i+1 < len(s) && s[i+1] == '\'' {
					b.WriteByte('\'')
					i += 2
					continue
				}
				i++
				if i < len(s) && s[i] == ':' {
					return b.String(), strings.TrimSpace(s[i+1:]), true
				}
				return "", "", false
			}
			b.WriteByte(s[i])
			i++
		}
		return "", "", false
	case '"':
		i := 1
		for i < len(s) {
			if s[i] == '\\' {
				i += 2
				continue
			}
			if s[i] == '"' {
				q, err := strconv.Unquote(s[:i+1])
				if err != nil {
					return "", "", false
				}
				i++
				if i < len(s) && s[i] == ':' {
					return q, strings.TrimSpace(s[i+1:]), true
				}
				return "", "", false
			}
			i++
		}
		return "", "", false
	case '&', '*', '!', '|', '>', '%', '@', '`', '-', '?', '[', '{':
		if s[0] == '@' || (s[0] == '-' && !strings.HasPrefix(s, "- ")) {
			// '@' and a leading '-' may begin plain scalars in principle; the generated format quotes them.
			return "", "", false
		}
		return "", "", false
	}
	if i := strings.Index(s, ": "); i >= 0 {
		return s[:i], strings.TrimSpace(s[i+2:]), true
	}
	if strings.HasSuffix(s, ":") {
		return s[:len(s)-1], "", true
	}
	return "", "", false
}

// scalar decodes a YAML scalar value (quoted or plain); ok is false for constructs the reader does not support.
func yamlScalar(v string) (string, bool) {
	if v == "" {
		return "", true
	}
	if i := strings.Index(v, " #"); i >= 0 && v[0] != '\'' && v[0] != '"' {
		v = strings.TrimSpace(v[:i])
	}
	switch v[0] {
	case '\'':
		if len(v) < 2 || v[len(v)-1] != '\'' {
			return "", false
		}
		return strings.ReplaceAll(v[1:len(v)-1], "''", "'"), true
	case '"':
		q, err := strconv.Unquote(v)
		return q, err == nil
	case '&', '*', '!', '|', '>', '[', '{':
		return "", false
	}
	return v, true
}

func parsePnpmLock(data []byte) *parseResult {
	res := newParseResult()
	if len(data) > maxManifestBytes {
		return res.fail("too_large", "lock file exceeds the size limit")
	}
	if !utf8.Valid(data) {
		return res.fail("malformed", "not UTF-8")
	}
	lines, ok := splitLines(data)
	if !ok {
		return res.fail("malformed", "too many lines")
	}
	// Top-level sections by indentation 0.
	type section struct{ start, end int }
	sections := map[string]section{}
	var names []string
	for i, l := range lines {
		if l == "" || strings.HasPrefix(l, "#") || l[0] == ' ' {
			continue
		}
		if l[0] == '\t' {
			res.unparsed("tab_indentation")
			continue
		}
		key, rest, ok := readYAMLKey(l)
		if !ok {
			res.unparsed("top_level_line")
			continue
		}
		if key == "lockfileVersion" {
			v, ok := yamlScalar(rest)
			if !ok {
				return res.fail("malformed", "lockfileVersion is unreadable")
			}
			res.FormatVersion = strp(v)
			continue
		}
		sections[key] = section{start: i + 1, end: len(lines)}
		names = append(names, key)
	}
	for idx, name := range names {
		s := sections[name]
		if idx+1 < len(names) {
			s.end = sections[names[idx+1]].start - 1
		}
		sections[name] = s
	}
	if res.FormatVersion == nil {
		return res.fail("malformed", "no lockfileVersion")
	}
	if !strings.HasPrefix(*res.FormatVersion, "9.") {
		return res.fail("unsupported", "lockfileVersion "+*res.FormatVersion+" is not 9.x")
	}
	imp, hasImp := sections["importers"]
	pkg, hasPkg := sections["packages"]
	if !hasImp {
		res.unparsed("missing_section_importers")
	}
	if !hasPkg {
		res.unparsed("missing_section_packages")
	}

	// importers
	type depSpec struct{ scope string }
	directScopes := map[string]map[string]bool{} // "name@version" -> scopes
	var importerPaths []string
	if hasImp {
		secOf := map[string]string{"dependencies": "runtime", "optionalDependencies": "optional", "devDependencies": "dev"}
		var impPath, secName, depName, depVer string
		flush := func() {}
		_ = flush
		emit := func(impPath, secName, depName, ver string) {
			scope := secOf[secName]
			if strings.HasPrefix(ver, "link:") {
				if validIdentity("npm", depName) && validText(ver, maxVersionBytes) {
					res.Rows = append(res.Rows, occRow{Locator: "/importers/" + impPath + "/" + secName + "/" + depName, Ecosystem: "npm",
						NameOriginal: depName, NameNormalized: depName, VersionOriginal: strp(ver), VersionState: "workspace", Direct: boolp(true),
						Scope: scope, ScopeBasis: "importer_section", SourceKind: "pnpm_link"})
				} else {
					res.unparsed("rejected_dependency")
				}
				return
			}
			base := ver
			if i := strings.Index(base, "("); i >= 0 {
				base = base[:i]
			}
			real := depName
			if j := strings.LastIndex(base, "@"); j > 0 { // alias: version names the real package@version
				real, base = base[:j], base[j+1:]
			}
			k := real + "@" + base
			if directScopes[k] == nil {
				directScopes[k] = map[string]bool{}
			}
			directScopes[k][scope] = true
		}
		haveVer := false
		pending := func() {
			if depName != "" && haveVer {
				emit(impPath, secName, depName, depVer)
			} else if depName != "" {
				res.unparsed("dependency_without_version")
			}
			depName, depVer, haveVer = "", "", false
		}
		for i := imp.start; i < imp.end && i < len(lines); i++ {
			l := lines[i]
			if strings.TrimSpace(l) == "" || strings.HasPrefix(strings.TrimSpace(l), "#") {
				continue
			}
			if strings.ContainsRune(l[:len(l)-len(strings.TrimLeft(l, " \t"))], '\t') {
				res.unparsed("tab_indentation")
				continue
			}
			indent := len(l) - len(strings.TrimLeft(l, " "))
			text := l[indent:]
			switch {
			case indent == 2:
				pending()
				key, _, ok := readYAMLKey(text)
				if !ok {
					res.unparsed("importer_key")
					impPath, secName = "", ""
					continue
				}
				impPath, secName = key, ""
				importerPaths = append(importerPaths, impPath)
			case indent == 4:
				pending()
				key, _, ok := readYAMLKey(text)
				if !ok {
					res.unparsed("importer_section_key")
					secName = ""
					continue
				}
				secName = key
			case indent == 6 && impPath != "" && secOf[secName] != "":
				pending()
				key, rest, ok := readYAMLKey(text)
				if !ok || rest != "" {
					res.unparsed("dependency_key")
					continue
				}
				depName = key
			case indent == 8 && depName != "":
				key, rest, ok := readYAMLKey(text)
				if !ok {
					res.unparsed("dependency_field")
					continue
				}
				if key == "version" {
					v, ok := yamlScalar(rest)
					if !ok || v == "" {
						res.unparsed("dependency_version")
						continue
					}
					depVer, haveVer = v, true
				}
			}
		}
		pending()
	}

	// packages: keys at indent 2
	if hasPkg {
		for i := pkg.start; i < pkg.end && i < len(lines); i++ {
			l := lines[i]
			if l == "" || strings.HasPrefix(strings.TrimSpace(l), "#") {
				continue
			}
			if len(l) < 3 || l[0] != ' ' || l[1] != ' ' || l[2] == ' ' {
				if strings.HasPrefix(l, "  ") {
					continue // deeper (indent > 2) lines are per-package fields: safe to ignore
				}
				if strings.ContainsRune(l, '\t') {
					res.unparsed("tab_indentation")
				}
				continue
			}
			key, _, ok := readYAMLKey(l[2:])
			if !ok {
				res.unparsed("package_key")
				continue
			}
			at := strings.LastIndex(key, "@")
			if at <= 0 {
				res.unparsed("package_key")
				continue
			}
			name, ver := key[:at], key[at+1:]
			row := occRow{Locator: "/packages/" + key, Ecosystem: "npm", NameOriginal: name, NameNormalized: name, VersionOriginal: strp(ver),
				VersionState: "exact", Scope: "unknown", ScopeBasis: "not_derived_transitive", SourceKind: "npm_registry", Direct: boolp(false)}
			switch {
			case !validIdentity("npm", name) || !validText(ver, maxVersionBytes):
				res.unparsed("rejected_name")
				continue
			case strings.HasPrefix(ver, "npm:"):
				row.VersionState, row.SourceKind = "unresolved_identity", "pnpm_alias"
			case strings.ContainsAny(ver, "/:"):
				row.VersionState, row.SourceKind = "non_registry", "pnpm_non_registry"
			}
			if scopes := directScopes[key]; scopes != nil {
				row.Direct = boolp(true)
				for _, s := range []string{"runtime", "optional", "dev"} {
					if scopes[s] {
						row.Scope, row.ScopeBasis = s, "importer_section"
						break
					}
				}
			}
			res.Rows = append(res.Rows, row)
		}
	}
	seen := map[string]bool{}
	for _, p := range importerPaths {
		d, ok := relDir(p)
		if ok && !seen[d] {
			seen[d] = true
			res.CoveredDirs = append(res.CoveredDirs, d)
		}
	}
	sort.Strings(res.CoveredDirs)
	finishRows(res)
	return res
}
