package main

// npm package-lock.json (lockfileVersion 2 and 3) and lockless package.json readers (I3-REQ-04).

import (
	"bytes"
	"encoding/json"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

type npmEntry struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Resolved             string            `json:"resolved"`
	Integrity            string            `json:"integrity"`
	Link                 bool              `json:"link"`
	Dev                  bool              `json:"dev"`
	Optional             bool              `json:"optional"`
	Peer                 bool              `json:"peer"`
	DevOptional          bool              `json:"devOptional"`
	InBundle             bool              `json:"inBundle"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
}

var npmTarballPathRE = regexp.MustCompile(`^/(.+)/-/[^/]+\.tgz$`)

func npmScope(e *npmEntry) string {
	switch {
	case e.DevOptional || (e.Dev && e.Optional):
		return "dev_optional"
	case e.Dev:
		return "dev"
	case e.Optional:
		return "optional"
	case e.Peer:
		return "peer"
	}
	return "runtime"
}

// registryOrigin reports whether resolved is an https tarball on registry.npmjs.org and returns the
// package name encoded in its path. It parses the URL; it never matches on a prefix.
func registryOrigin(resolved string) (bool, string) {
	u, err := url.Parse(resolved)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Port() != "" || !strings.EqualFold(u.Hostname(), "registry.npmjs.org") {
		return false, ""
	}
	m := npmTarballPathRE.FindStringSubmatch(u.Path)
	if m == nil {
		return false, ""
	}
	return true, m[1]
}

func parseNpmLock(data []byte) *parseResult {
	res := newParseResult()
	if len(data) > maxManifestBytes {
		return res.fail("too_large", "lock file exceeds the size limit")
	}
	if !jsonDepthOK(data, maxJSONDepth) {
		return res.fail("malformed", "JSON nesting is deeper than the limit")
	}
	var doc struct {
		LockfileVersion int                        `json:"lockfileVersion"`
		Packages        map[string]json.RawMessage `json:"packages"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&doc); err != nil {
		return res.fail("malformed", "not a JSON object: "+truncErr(err))
	}
	ver := doc.LockfileVersion
	if ver != 2 && ver != 3 {
		return res.fail("unsupported", "lockfileVersion is not 2 or 3")
	}
	res.FormatVersion = strp(map[int]string{2: "2", 3: "3"}[ver])
	if doc.Packages == nil {
		return res.fail("malformed", "no packages map")
	}
	entries := map[string]*npmEntry{}
	for key, raw := range doc.Packages {
		var e npmEntry
		if err := json.Unmarshal(raw, &e); err != nil {
			res.unparsed("package_entry")
			continue
		}
		entries[key] = &e
	}
	direct := map[string]bool{}
	if root, ok := entries[""]; ok {
		for _, m := range []map[string]string{root.Dependencies, root.DevDependencies, root.OptionalDependencies, root.PeerDependencies} {
			for name := range m {
				direct[name] = true
			}
		}
	}
	keys := make([]string, 0, len(entries))
	for k := range entries {
		if k != "" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	dirs := map[string]bool{"": true} // the lock's own directory is covered by its root entry
	for _, key := range keys {
		e := entries[key]
		if !validText(key, 1024) {
			res.unparsed("rejected_key")
			continue
		}
		installed, top := key, false
		if i := strings.LastIndex(key, "node_modules/"); i >= 0 {
			installed = key[i+len("node_modules/"):]
			top = key == "node_modules/"+installed
		} else if d, ok := relDir(key); ok {
			dirs[d] = true
		}
		name := e.Name
		if name == "" {
			name = installed
		}
		if !validIdentity("npm", name) {
			res.unparsed("rejected_name")
			continue
		}
		row := occRow{Locator: "/packages/" + key, Ecosystem: "npm", NameOriginal: name, NameNormalized: name,
			Direct: boolp(top && direct[installed]), Scope: npmScope(e), ScopeBasis: "lock_flag", SourceKind: "npm_registry",
			IntegrityRecorded: boolp(e.Integrity != "")}
		if installed != name {
			row.InstalledName, row.Alias = installed, boolp(true)
		}
		if e.Version != "" {
			if !validText(e.Version, maxVersionBytes) {
				res.unparsed("rejected_version")
				continue
			}
			row.VersionOriginal = strp(e.Version)
		}
		switch reg, encoded := registryOrigin(e.Resolved); {
		case e.Link:
			row.VersionState, row.SourceKind = "workspace", "npm_link"
		case !strings.Contains(key, "node_modules/"):
			row.VersionState, row.SourceKind = "workspace", "npm_workspace_package"
		case reg && encoded == name:
			if e.Version != "" {
				row.VersionState = "exact"
			} else {
				row.VersionState = "missing"
			}
		case reg:
			row.VersionState = "unresolved_identity"
		case e.Resolved == "" && e.InBundle:
			row.VersionState, row.SourceKind = "non_registry", "npm_bundled"
		default:
			row.VersionState, row.SourceKind = "non_registry", "npm_non_registry"
		}
		res.Rows = append(res.Rows, row)
	}
	for d := range dirs {
		res.CoveredDirs = append(res.CoveredDirs, d)
	}
	sort.Strings(res.CoveredDirs)
	finishRows(res)
	return res
}

func truncErr(err error) string {
	s := err.Error()
	if len(s) > 120 {
		s = s[:120]
	}
	return s
}

// parsePackageJSON reads a package.json that no lock covers: declared specifiers as `range` rows.
func parsePackageJSON(data []byte) *parseResult {
	res := newParseResult()
	if len(data) > maxManifestBytes {
		return res.fail("too_large", "package.json exceeds the size limit")
	}
	if !jsonDepthOK(data, maxJSONDepth) {
		return res.fail("malformed", "JSON nesting is deeper than the limit")
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil {
		return res.fail("malformed", "not a JSON object: "+truncErr(err))
	}
	for _, sec := range []struct{ name, scope string }{{"dependencies", "runtime"}, {"devDependencies", "dev"},
		{"optionalDependencies", "optional"}, {"peerDependencies", "peer"}} {
		raw, ok := doc[sec.name]
		if !ok {
			continue
		}
		var deps map[string]any
		if err := json.Unmarshal(raw, &deps); err != nil {
			res.unparsed("dependency_section")
			continue
		}
		for name, spec := range deps {
			s, isStr := spec.(string)
			if !isStr || !validIdentity("npm", name) || !validText(s, maxVersionBytes) {
				res.unparsed("rejected_dependency")
				continue
			}
			res.Rows = append(res.Rows, occRow{Locator: "/" + sec.name + "/" + name, Ecosystem: "npm", NameOriginal: name, NameNormalized: name,
				VersionOriginal: strp(s), VersionState: "range", Direct: boolp(true), Scope: sec.scope, ScopeBasis: "package_json_section",
				SourceKind: "npm_declared"})
		}
	}
	finishRows(res)
	return res
}
