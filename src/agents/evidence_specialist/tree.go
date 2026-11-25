package main

// Source trees, candidate patches and their scope checks (I2-REQ-07). A tree is built only from
// digest-pinned blobs listed in a source manifest; a candidate is a unified diff whose scope is
// checked before anything runs.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const pinnedGoVersion = "go1.24.7"

type sourceManifest struct {
	Schema string `json:"schema"`
	Files  []struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
		Bytes  int    `json:"bytes"`
	} `json:"files"`
}

type checkSpec struct {
	Schema      string   `json:"schema"`
	OracleFiles []string `json:"oracle_files"`
	Checks      []struct {
		CheckID  string   `json:"check_id"`
		Argv     []string `json:"argv"`
		Required bool     `json:"required"`
	} `json:"checks"`
}

// allowlistedChecks are the only commands change_validate will run (contract section 3.3).
var allowlistedChecks = map[string][]string{
	"modverify": {"go", "mod", "verify"},
	"build":     {"go", "build", "./..."},
	"vet":       {"go", "vet", "./..."},
	"test":      {"go", "test", "-count=1", "-json", "-timeout", "60s", "./..."},
	"modlist":   {"go", "list", "-m", "-json", "all"},
}

var checkLimits = map[string]Limits2{"modverify": limVerify, "build": limBuild, "vet": limBuild, "test": limBuild, "modlist": limList}

// prepFail describes why a tree could not be prepared: either a request rejection or a failed result.
type prepFail struct {
	rejectCode, rejectMsg string
	errCode, errMsg       string
}

type prepared struct {
	ws, tree    string
	manifest    *sourceManifest
	baseSHA     map[string]string
	patchBytes  []byte
	patchDigest string
	patchFiles  []string
	spec        *checkSpec
	norm        *pathNormalizer
	module      string
}

func (p *prepared) cleanup() { os.RemoveAll(p.ws) }

var modulePathRE = regexp.MustCompile(`(?m)^module\s+(\S+)`)

// prepareTree implements the first steps of change_validate and govulncheck_source: toolchain and
// sandbox checks, candidate/context agreement, patch scope and oracle checks, materialization,
// git apply, oracle digests and the unexpected-change comparison. Nothing is executed before the
// scope and oracle checks pass.
func (s *Server) prepareTree(ctx context.Context, t *TaskRequest, jobDeadline time.Time, needSpec bool) (*prepared, *prepFail) {
	w := s.worker
	patchRef := inputByRole(t, "candidate_patch")
	switch {
	case patchRef != nil && (t.Context.CandidateID == nil || *t.Context.CandidateID != patchRef.Digest):
		return nil, &prepFail{rejectCode: "candidate_mismatch", rejectMsg: "context.candidate_id must equal the candidate_patch digest."}
	case patchRef == nil && t.Context.CandidateID != nil:
		return nil, &prepFail{rejectCode: "candidate_mismatch", rejectMsg: "context.candidate_id is set but no candidate_patch input was given."}
	}
	srcRef := inputByRole(t, "source_manifest")
	if srcRef == nil {
		return nil, &prepFail{rejectCode: "invalid_request", rejectMsg: "A source_manifest input is required."}
	}
	rawManifest, err := s.store.ReadMax(srcRef.Digest, 1<<20)
	if err != nil {
		return nil, storeFail(err, "source manifest")
	}
	var man sourceManifest
	if json.Unmarshal(rawManifest, &man) != nil || man.Schema != "opentrace.source_manifest/1" || len(man.Files) == 0 || len(man.Files) > 200 {
		return nil, &prepFail{errCode: "artifact_integrity_failure", errMsg: "The source manifest is malformed."}
	}
	spec := &checkSpec{}
	if needSpec {
		specRef := inputByRole(t, "check_spec")
		if specRef == nil {
			return nil, &prepFail{rejectCode: "invalid_request", rejectMsg: "A check_spec input is required."}
		}
		raw, err := s.store.ReadMax(specRef.Digest, 1<<20)
		if err != nil {
			return nil, storeFail(err, "check spec")
		}
		if bad := validateSpec(raw, spec); bad != "" {
			return nil, &prepFail{rejectCode: "invalid_request", rejectMsg: bad}
		}
	}
	oracle := spec.OracleFiles
	if len(oracle) == 0 {
		oracle = []string{"negotiate_test.go"}
	}
	var patchBytes []byte
	var patchFiles []string
	if patchRef != nil {
		patchBytes, err = s.store.ReadMax(patchRef.Digest, 256<<10)
		if err != nil {
			return nil, storeFail(err, "candidate patch")
		}
		files, code, detail := scanPatch(patchBytes, oracle)
		if code != "" {
			return nil, &prepFail{rejectCode: code, rejectMsg: detail}
		}
		patchFiles = files
	}
	if w.sandbox == nil {
		return nil, &prepFail{errCode: "sandbox_unavailable", errMsg: "A network namespace could not be created; nothing was run."}
	}
	if w.goVersion != pinnedGoVersion {
		return nil, &prepFail{errCode: "toolchain_mismatch", errMsg: fmt.Sprintf("Expected %s, found %s; nothing was run.", pinnedGoVersion, w.goVersion)}
	}
	if w.modcache == "" || w.gitBin == "" {
		return nil, &prepFail{errCode: "module_unavailable", errMsg: "The module cache or git is not configured; nothing was run."}
	}
	ws, err := os.MkdirTemp("", "otb-i2-")
	if err != nil {
		return nil, &prepFail{errCode: "worker_failed", errMsg: "workspace could not be created"}
	}
	p := &prepared{ws: ws, tree: filepath.Join(ws, "tree"), manifest: &man, baseSHA: map[string]string{}, patchBytes: patchBytes,
		patchFiles: patchFiles, spec: spec}
	if patchRef != nil {
		p.patchDigest = patchRef.Digest
	}
	for _, d := range []string{p.tree, filepath.Join(ws, "gocache"), filepath.Join(ws, "gopath")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			p.cleanup()
			return nil, &prepFail{errCode: "worker_failed", errMsg: "workspace could not be created"}
		}
	}
	for _, f := range man.Files {
		clean := path.Clean(f.Path)
		if clean != f.Path || strings.HasPrefix(clean, "/") || strings.HasPrefix(clean, "..") || !digestRE.MatchString("sha256:"+f.SHA256) {
			p.cleanup()
			return nil, &prepFail{errCode: "artifact_integrity_failure", errMsg: "The source manifest names an unsafe path or digest."}
		}
		data, err := s.store.ReadMax("sha256:"+f.SHA256, 1<<20)
		if err != nil {
			p.cleanup()
			return nil, storeFail(err, "source file "+f.Path)
		}
		dest := filepath.Join(p.tree, filepath.FromSlash(f.Path))
		_ = os.MkdirAll(filepath.Dir(dest), 0o755)
		if os.WriteFile(dest, data, 0o644) != nil {
			p.cleanup()
			return nil, &prepFail{errCode: "worker_failed", errMsg: "source file could not be written"}
		}
		p.baseSHA[f.Path] = f.SHA256
		if f.Path == "go.mod" {
			if m := modulePathRE.FindSubmatch(data); m != nil {
				p.module = string(m[1])
			}
		}
	}
	p.norm = newNormalizer(pathRule{ws, "<TMP>"}, pathRule{w.goroot, "<GOROOT>"}, pathRule{w.modcache, "<GOMODCACHE>"})
	env := jobEnv(w, ws)
	if patchRef != nil {
		patchPath := filepath.Join(ws, "patch.diff")
		if os.WriteFile(patchPath, patchBytes, 0o600) != nil {
			p.cleanup()
			return nil, &prepFail{errCode: "worker_failed", errMsg: "patch could not be written"}
		}
		for _, args := range [][]string{{"apply", "--check", "-p1", patchPath}, {"apply", "-p1", patchPath}} {
			res := w.sandbox.Run(ctx, append([]string{w.gitBin}, args...), p.tree, env, limGitApply, jobDeadline)
			if res.Err != nil || res.TimedOut || res.Exit != 0 {
				p.cleanup()
				return nil, &prepFail{errCode: "patch_apply_failed", errMsg: "The candidate patch does not apply to the baseline tree."}
			}
		}
	}
	snap := snapshotTree(p.tree)
	for _, o := range oracle {
		if want, ok := p.baseSHA[o]; ok && snap[o] != want {
			p.cleanup()
			return nil, &prepFail{rejectCode: "oracle_modified", rejectMsg: "An oracle file differs from the baseline after the patch."}
		}
	}
	return p, nil
}

func storeFail(err error, what string) *prepFail {
	if errors.Is(err, errIntegrity) {
		return &prepFail{errCode: "artifact_integrity_failure", errMsg: "The " + what + " bytes do not match their digest."}
	}
	return &prepFail{errCode: "artifact_not_found", errMsg: "The " + what + " is not in the store."}
}

func validateSpec(raw []byte, spec *checkSpec) string {
	if json.Unmarshal(raw, spec) != nil || spec.Schema != "opentrace.required_checks/1" || len(spec.Checks) == 0 {
		return "The check spec is malformed."
	}
	for _, c := range spec.Checks {
		want, ok := allowlistedChecks[c.CheckID]
		if !ok || strings.Join(want, "\x00") != strings.Join(c.Argv, "\x00") {
			return "The check spec names a command outside the allowlist: " + c.CheckID + "."
		}
	}
	return ""
}

func snapshotTree(root string) map[string]string {
	out := map[string]string{}
	_ = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			out[filepath.ToSlash(rel)] = "non-regular"
			return nil
		}
		data, rerr := os.ReadFile(p)
		if rerr != nil {
			out[filepath.ToSlash(rel)] = "unreadable"
			return nil
		}
		sum := sha256.Sum256(data)
		out[filepath.ToSlash(rel)] = hex.EncodeToString(sum[:])
		return nil
	})
	return out
}

// unexpectedChanges lists files that differ from manifest-plus-patch: anything changed, added or
// removed that the patch headers did not name.
func unexpectedChanges(base map[string]string, patched []string, snap map[string]string) []string {
	named := map[string]bool{}
	for _, f := range patched {
		named[f] = true
	}
	var out []string
	for p, sum := range snap {
		want, inBase := base[p]
		switch {
		case sum == "non-regular" || sum == "unreadable":
			out = append(out, "non_regular_or_unreadable:"+p)
		case !inBase && !named[p]:
			out = append(out, "unexpected_file:"+p)
		case inBase && sum != want && !named[p]:
			out = append(out, "modified:"+p)
		}
	}
	for p := range base {
		if _, ok := snap[p]; !ok && !named[p] {
			out = append(out, "deleted:"+p)
		}
	}
	sort.Strings(out)
	if out == nil {
		out = []string{}
	}
	return out
}

// ---- patch scope -------------------------------------------------------------------------------

func inPatchScope(p string) bool {
	if p == "" || strings.HasPrefix(p, "/") || strings.Contains(p, "\\") || path.Clean(p) != p {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." || seg == "." || seg == "" || seg == "vendor" || seg == ".git" {
			return false
		}
	}
	if p == "go.mod" || p == "go.sum" {
		return true
	}
	return strings.HasSuffix(p, ".go") && !strings.HasSuffix(p, "_test.go")
}

// scanPatch returns the patched file set, or a rejection code and detail. An oracle file touched by
// the patch is `oracle_modified` (more specific); anything else outside the allowlist is
// `patch_scope_violation`: other paths, "..", absolute paths, renames, copies, mode changes,
// symlinks, binary patches, go.work, vendor/.
func scanPatch(patch []byte, oracle []string) ([]string, string, string) {
	isOracle := map[string]bool{}
	for _, o := range oracle {
		isOracle[o] = true
	}
	seen := map[string]bool{}
	var files []string
	violation := func(detail string) ([]string, string, string) { return nil, "patch_scope_violation", detail }
	headerPath := func(s, prefix string) (string, bool) {
		s = strings.TrimSpace(s)
		if i := strings.IndexAny(s, "\t"); i >= 0 {
			s = s[:i]
		}
		if s == "/dev/null" {
			return "", true
		}
		if !strings.HasPrefix(s, prefix) {
			return s, false
		}
		return strings.TrimPrefix(s, prefix), true
	}
	for _, line := range strings.Split(string(patch), "\n") {
		switch {
		case strings.HasPrefix(line, "GIT binary patch"), strings.HasPrefix(line, "Binary files"):
			return violation("binary patches are not allowed")
		case strings.HasPrefix(line, "rename "), strings.HasPrefix(line, "copy "), strings.HasPrefix(line, "similarity index"),
			strings.HasPrefix(line, "dissimilarity index"):
			return violation("renames and copies are not allowed")
		case strings.HasPrefix(line, "old mode"), strings.HasPrefix(line, "new mode"):
			return violation("mode changes are not allowed")
		case strings.HasPrefix(line, "new file mode"), strings.HasPrefix(line, "deleted file mode"):
			if !strings.HasSuffix(strings.TrimSpace(line), "100644") {
				return violation("only regular non-executable files are allowed")
			}
		case strings.HasPrefix(line, "--- "), strings.HasPrefix(line, "+++ "):
			prefix := "a/"
			if strings.HasPrefix(line, "+++ ") {
				prefix = "b/"
			}
			p, ok := headerPath(line[4:], prefix)
			if !ok {
				return violation("patch paths must use the a/ and b/ prefixes")
			}
			if p == "" {
				continue
			}
			if isOracle[p] {
				return nil, "oracle_modified", "The patch changes oracle file " + p + "."
			}
			if !inPatchScope(p) {
				return violation("path " + p + " is outside the patch scope")
			}
			if !seen[p] {
				seen[p] = true
				files = append(files, p)
			}
		}
	}
	if len(files) == 0 {
		return violation("the patch names no file")
	}
	sort.Strings(files)
	return files, "", ""
}
