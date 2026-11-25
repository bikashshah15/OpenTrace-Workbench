package main

// go.mod reader (I3-REQ-04 "go_mod"): declared requirements only, no toolchain, no network, no `go` subprocess.

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var goModVersionRE = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)

type goTok struct {
	text   string
	quoted bool
}

// goTokenize splits one go.mod line into tokens, honoring "..." and `...` quoting and // comments.
// It returns the tokens and the comment text (without the //).
func goTokenize(line string) ([]goTok, string, bool) {
	var toks []goTok
	i := 0
	for i < len(line) {
		c := line[i]
		switch {
		case c == ' ' || c == '\t':
			i++
		case c == '/' && i+1 < len(line) && line[i+1] == '/':
			return toks, strings.TrimSpace(line[i+2:]), true
		case c == '(' || c == ')':
			toks = append(toks, goTok{text: string(c)})
			i++
		case c == '"':
			// An interpreted string: escapes are decoded exactly as Go does, so an escaped control character
			// becomes a real control character and is rejected by the identity check, never dropped silently.
			j := i + 1
			for j < len(line) && line[j] != '"' {
				if line[j] == '\\' && j+1 < len(line) {
					j++
				}
				j++
			}
			if j >= len(line) {
				return toks, "", false
			}
			text, err := strconv.Unquote(line[i : j+1])
			if err != nil {
				return toks, "", false
			}
			toks = append(toks, goTok{text: text, quoted: true})
			i = j + 1
		case c == '`':
			j := strings.IndexByte(line[i+1:], '`')
			if j < 0 {
				return toks, "", false
			}
			toks = append(toks, goTok{text: line[i+1 : i+1+j], quoted: true})
			i += j + 2
		default:
			j := i
			for j < len(line) && line[j] != ' ' && line[j] != '\t' && line[j] != '(' && line[j] != ')' &&
				!(line[j] == '/' && j+1 < len(line) && line[j+1] == '/') {
				j++
			}
			if j == i { // a lone '/' or similar is consumed to guarantee progress
				j = i + 1
			}
			toks = append(toks, goTok{text: line[i:j]})
			i = j
		}
	}
	return toks, "", true
}

func isIndirectComment(c string) bool {
	c = strings.TrimSpace(c)
	return c == "indirect" || strings.HasPrefix(c, "indirect;")
}

func isLocalPath(p string) bool {
	return strings.HasPrefix(p, "./") || strings.HasPrefix(p, "../") || strings.HasPrefix(p, "/") || p == "." || p == ".." ||
		(len(p) >= 2 && p[1] == ':')
}

type goReq struct {
	line     int
	path     string
	version  string
	indirect bool
}

type goReplace struct {
	oldPath, oldVer string
	newPath, newVer string
}

// goSumHashes returns the set of "module version" pairs that have an h1: line in go.sum.
func goSumHashes(data []byte) map[string]bool {
	out := map[string]bool{}
	if data == nil {
		return out
	}
	lines, ok := splitLines(data)
	if !ok {
		return out
	}
	for _, l := range lines {
		f := strings.Fields(l)
		if len(f) == 3 && strings.HasPrefix(f[2], "h1:") && !strings.HasSuffix(f[1], "/go.mod") {
			out[f[0]+" "+f[1]] = true
		}
	}
	return out
}

func parseGoMod(data []byte, goSum []byte) *parseResult {
	res := newParseResult()
	if len(data) > maxManifestBytes {
		return res.fail("too_large", "go.mod exceeds the size limit")
	}
	lines, ok := splitLines(data)
	if !ok {
		return res.fail("malformed", "too many lines")
	}
	var reqs []goReq
	var repls []goReplace
	block := ""
	for n, raw := range lines {
		lineNo := n + 1
		toks, comment, ok := goTokenize(raw)
		if !ok {
			res.unparsed("unterminated_quote")
			continue
		}
		if len(toks) == 0 {
			continue
		}
		if block != "" {
			if len(toks) == 1 && toks[0].text == ")" {
				block = ""
				continue
			}
			switch block {
			case "require":
				if len(toks) != 2 {
					res.unparsed("require_entry")
					continue
				}
				reqs = append(reqs, goReq{lineNo, toks[0].text, toks[1].text, isIndirectComment(comment)})
			case "replace":
				if r, ok := parseReplace(toks); ok {
					repls = append(repls, r)
				} else {
					res.unparsed("replace_entry")
				}
			case "exclude", "retract", "tool", "ignore", "godebug":
				// counted by directive only; entries carry no inventory
			}
			continue
		}
		head := toks[0].text
		rest := toks[1:]
		if len(rest) == 1 && rest[0].text == "(" {
			switch head {
			case "require", "replace", "exclude", "retract", "tool", "ignore", "godebug":
				block = head
			default:
				res.unparsed("unknown_block_" + head)
				block = "unknown"
			}
			continue
		}
		switch head {
		case "module", "go", "toolchain", "exclude", "retract", "tool", "ignore", "godebug":
		case "require":
			if len(rest) != 2 {
				res.unparsed("require_entry")
				continue
			}
			reqs = append(reqs, goReq{lineNo, rest[0].text, rest[1].text, isIndirectComment(comment)})
		case "replace":
			if r, ok := parseReplace(rest); ok {
				repls = append(repls, r)
			} else {
				res.unparsed("replace_entry")
			}
		default:
			res.unparsed("unknown_directive")
		}
	}
	if block != "" {
		res.unparsed("unterminated_block")
	}
	sums := goSumHashes(goSum)
	haveSum := goSum != nil
	for _, r := range reqs {
		if !validIdentity("Go", r.path) {
			res.unparsed("rejected_name")
			continue
		}
		row := occRow{Locator: fmt.Sprintf("/require/%d", r.line), Ecosystem: "Go", NameOriginal: r.path, NameNormalized: r.path,
			Direct: boolp(!r.indirect), Scope: "unknown", ScopeBasis: "go_mod_has_no_scope", SourceKind: "go_module"}
		if validText(r.version, maxVersionBytes) && goModVersionRE.MatchString(r.version) {
			row.VersionOriginal, row.VersionState = strp(r.version), "exact"
		} else if validText(r.version, maxVersionBytes) {
			row.VersionOriginal, row.VersionState = strp(r.version), "missing"
		} else {
			res.unparsed("rejected_version")
			continue
		}
		for _, rp := range repls {
			if rp.oldPath != r.path || (rp.oldVer != "" && rp.oldVer != r.version) {
				continue
			}
			if isLocalPath(rp.newPath) {
				row.VersionState, row.SourceKind = "local_replace", "go_local_replace"
			} else {
				row.VersionState, row.ReplacedBy = "replaced_module", strings.TrimSpace(rp.newPath+" "+rp.newVer)
			}
		}
		if haveSum && row.VersionState == "exact" {
			row.IntegrityRecorded = boolp(sums[r.path+" "+r.version])
		}
		res.Rows = append(res.Rows, row)
	}
	finishRows(res)
	return res
}

func parseReplace(toks []goTok) (goReplace, bool) {
	arrow := -1
	for i, t := range toks {
		if t.text == "=>" && !t.quoted {
			arrow = i
		}
	}
	if arrow < 1 || arrow > 2 || len(toks)-arrow-1 < 1 || len(toks)-arrow-1 > 2 {
		return goReplace{}, false
	}
	r := goReplace{oldPath: toks[0].text, newPath: toks[arrow+1].text}
	if arrow == 2 {
		r.oldVer = toks[1].text
	}
	if len(toks)-arrow-1 == 2 {
		r.newVer = toks[arrow+2].text
	}
	return r, true
}
