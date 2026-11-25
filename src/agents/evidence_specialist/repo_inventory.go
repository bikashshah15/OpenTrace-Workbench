package main

// repo_inventory (I3-REQ-04): offline, static interpretation of one pinned manifest blob. B reads only the
// digests listed in the bundle manifest it was given, re-checks every path against its own copy of the
// manifest policy, verifies the blob's digest and git blob id, runs the matching bounded parser and emits
// per-manifest evidence plus one digest-pinned occurrence table. It never executes cohort code, never
// starts a subprocess and never touches the network.

import (
	"context"
	"crypto/sha1" // #nosec G505 -- git object ids are SHA-1 by definition; used only to verify a blob id
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"
)

const opRepoInventory = "repo_inventory"

func init() { registerV3(opRepoInventory, "inventory", repoInventoryHandler) }

// B's own copy of the manifest selection policy (contracts/cohort/v1/manifest_policy.json): core applies
// the policy and sends the selection; B re-checks every path (I3-REQ-04).
var (
	srcBasenameKinds = map[string]string{"go.mod": "go_mod", "go.sum": "go_sum", "go.work": "go_work", "package.json": "package_json",
		"package-lock.json": "npm_lock", "npm-shrinkwrap.json": "npm_lock", "pnpm-lock.yaml": "pnpm_lock",
		"pnpm-workspace.yaml": "pnpm_workspace", "yarn.lock": "yarn_lock", "uv.lock": "uv_lock", "poetry.lock": "poetry_lock",
		"Pipfile.lock": "pipfile_lock", "pyproject.toml": "pyproject"}
	srcRequirementsRE = regexp.MustCompile(`^requirements.*\.txt$`)
	srcExcludedSegs   = map[string]bool{"node_modules": true, "vendor": true, "testdata": true, ".git": true}
	hex40RE           = regexp.MustCompile(`^[0-9a-f]{40}$`)
	repoNameRE        = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$`)
)

// inventoryParsers maps a manifest kind to its parser; package_json is the lockless declared-only reader.
var inventoryKinds = map[string]bool{"go_mod": true, "npm_lock": true, "pnpm_lock": true, "uv_lock": true, "package_json": true}

func kindOfBasename(base string) string {
	if k, ok := srcBasenameKinds[base]; ok {
		return k
	}
	if srcRequirementsRE.MatchString(base) {
		return "requirements_txt"
	}
	return ""
}

// srcPathProblem mirrors core's path validation (I3-REQ-03 item 3).
func srcPathProblem(p string) string {
	switch {
	case p == "":
		return "empty_path"
	case len(p) > 512:
		return "too_long"
	case strings.ContainsRune(p, 0):
		return "nul_byte"
	case !validText(p, 512):
		return "control_character_or_encoding"
	case strings.HasPrefix(p, "/"):
		return "absolute_path"
	case strings.Contains(p, "\\"):
		return "backslash"
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return "dot_segment"
		}
	}
	return ""
}

func pathExcluded(p string) bool {
	segs := strings.Split(p, "/")
	for _, s := range segs[:len(segs)-1] {
		if srcExcludedSegs[s] {
			return true
		}
	}
	return false
}

// srcFile is one manifest entry of a source bundle. Blob is the artifact digest of the verbatim bytes
// ("" when the content was not read); Hint records why a listed path was not read.
type srcFile struct {
	Path    string `json:"path"`
	Kind    string `json:"kind"`
	GitBlob string `json:"git_blob"`
	SHA256  string `json:"sha256"`
	Bytes   int    `json:"bytes"`
	Mode    string `json:"mode"`
	Blob    string `json:"blob"`
	Hint    string `json:"hint"`
}

type srcBundle struct {
	Schema                string    `json:"schema"`
	Kind                  string    `json:"kind"`
	Repo                  string    `json:"repo"`
	Commit                string    `json:"commit"`
	Tree                  string    `json:"tree"`
	SourceCaptureSetID    string    `json:"source_capture_set_id"`
	ListingDigest         string    `json:"listing_digest"`
	SelectedManifestCount int       `json:"selected_manifest_count"`
	ExcludedByPolicyCount int       `json:"excluded_by_policy_count"`
	EmitScope             bool      `json:"emit_scope"`
	Manifest              *srcFile  `json:"manifest"`
	Companions            []srcFile `json:"companions"`
	Siblings              []srcFile `json:"siblings"` // every selected manifest path of the repository (path, kind)
	Extras                []srcFile `json:"extras"`   // listed paths with no inventory task, reported on the first task of the repository
}

func gitBlobID(data []byte) string {
	h := sha1.New() // #nosec G401 -- git object id, not a security digest
	fmt.Fprintf(h, "blob %d\x00", len(data))
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

func contentSHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func dirOf(p string) string {
	d := path.Dir(p)
	if d == "." {
		return ""
	}
	return d
}

// readVerified returns the bytes of an entry after checking size, sha256 and git blob id.
func (s *Server) readVerified(f *srcFile) ([]byte, error) {
	if f.Blob == "" || !digestRE.MatchString(f.Blob) {
		return nil, errors.New("entry has no readable blob")
	}
	data, err := s.store.ReadMax(f.Blob, maxManifestBytes)
	if err != nil {
		return nil, err
	}
	if len(data) != f.Bytes || contentSHA256(data) != f.SHA256 || gitBlobID(data) != f.GitBlob {
		return nil, errIntegrity
	}
	return data, nil
}

// safeParse runs a parser and turns a panic into a malformed manifest (limits L5).
func safeParse(f func() *parseResult) (res *parseResult) {
	defer func() {
		if r := recover(); r != nil {
			res = newParseResult().fail("malformed", "parser panic recovered")
		}
	}()
	return f()
}

func parseByKind(kind string, data, goSum []byte) *parseResult {
	return safeParse(func() *parseResult {
		switch kind {
		case "go_mod":
			return parseGoMod(data, goSum)
		case "npm_lock":
			return parseNpmLock(data)
		case "pnpm_lock":
			return parsePnpmLock(data)
		case "uv_lock":
			return parseUvLock(data)
		case "package_json":
			return parsePackageJSON(data)
		}
		return newParseResult().fail("unsupported", "kind "+kind+" is not parsed")
	})
}

// statusFor decides the manifest_status of a listed path that has no inventory task.
func statusFor(f srcFile, siblings []srcFile) (status, coveredBy, reason string) {
	switch {
	case strings.HasPrefix(f.Hint, "mode_"):
		return "unsupported", "", "git mode " + strings.TrimPrefix(f.Hint, "mode_") + " is not a regular file; not read"
	case f.Hint == "too_large":
		return "too_large", "", fmt.Sprintf("blob of %d bytes exceeds the read limit; not read", f.Bytes)
	case strings.HasPrefix(f.Hint, "rejected_"):
		return "unsupported", "", "path rejected (" + strings.TrimPrefix(f.Hint, "rejected_") + "); never used as a path"
	case f.Hint == "excluded_path_segment":
		return "excluded_by_policy", "", "path contains an excluded segment"
	}
	dir := dirOf(f.Path)
	find := func(kind string) string {
		for _, s := range siblings {
			if s.Kind == kind && dirOf(s.Path) == dir {
				return s.Path
			}
		}
		return ""
	}
	switch f.Kind {
	case "go_sum":
		if m := find("go_mod"); m != "" {
			return "recognized_not_inventoried", m, "go.sum is read only as the companion of its go.mod"
		}
		return "recognized_not_inventoried", "", "no go.mod in the same directory"
	case "pnpm_workspace":
		if l := find("pnpm_lock"); l != "" {
			return "recognized_not_inventoried", l, "workspace file recognized; membership is read from the lock importers"
		}
		return "unsupported", "", "workspace file without a pnpm lock in the same directory"
	case "pyproject", "package_json":
		return "lock_absent", "", "no lock file covers this manifest"
	}
	return "unsupported", "", "kind " + f.Kind + " is not parsed in this increment"
}

func repoInventoryHandler(s *Server, ctx context.Context, t *TaskRequest, jobDeadline time.Time, tokens []Part) *Message {
	res := s.newV3Result(t, opRepoInventory)
	unsupportedRequirements(res, t, opRepoInventory, "inventory")
	rej := func(code, msg string) *Message { return s.rejectV3(tokens, false, code, msg, t.TaskID, t.RunID) }
	if *t.Budget.MaxWorkerJobs < 1 {
		return s.failV2(res, t, tokens, "budget_exhausted", "The task budget allows no worker job.")
	}
	ref := inputByRole(t, "bundle_manifest")
	if ref == nil {
		return rej("invalid_request", "A bundle_manifest input is required.")
	}
	raw, err := s.store.ReadMax(ref.Digest, maxBundleBytes)
	if err != nil {
		code := "artifact_not_found"
		if errors.Is(err, errIntegrity) {
			code = "artifact_integrity_failure"
		}
		return s.failV2(res, t, tokens, code, "The bundle manifest could not be read from the store.")
	}
	var b srcBundle
	if json.Unmarshal(raw, &b) != nil || b.Kind != "source" || b.Manifest == nil {
		return s.failV2(res, t, tokens, "artifact_integrity_failure", "The bundle manifest is not a source bundle.")
	}
	switch {
	case !repoNameRE.MatchString(b.Repo) || !hex40RE.MatchString(b.Commit) || !hex40RE.MatchString(b.Tree):
		return rej("invalid_request", "The bundle names an invalid repository, commit or tree.")
	case t.Context.RepoID != "github.com/"+b.Repo || t.Context.RequestedRevision != b.Commit:
		return rej("context_mismatch", "The task context does not name the bundle's repository and pinned commit.")
	case t.Context.ObservedRevision != nil && *t.Context.ObservedRevision != b.Commit:
		return rej("context_mismatch", "observed_revision differs from the pinned commit.")
	case b.SourceCaptureSetID != t.CaptureSetID:
		return rej("capture_mismatch", "The bundle's source_capture_set_id differs from the task's.")
	}
	m := b.Manifest
	if p := srcPathProblem(m.Path); p != "" || pathExcluded(m.Path) {
		return rej("invalid_request", "The manifest path is not an allowed manifest path.")
	}
	if kind := kindOfBasename(path.Base(m.Path)); kind == "" || kind != m.Kind || !inventoryKinds[m.Kind] {
		return rej("invalid_request", "The manifest kind does not match its basename or is not an inventory kind.")
	}
	if ctx.Err() != nil || time.Now().After(jobDeadline) {
		return s.failV2(res, t, tokens, "worker_timeout", "The task deadline passed before analysis.")
	}
	data, err := s.readVerified(m)
	if err != nil {
		code := "artifact_not_found"
		if errors.Is(err, errIntegrity) {
			code = "artifact_integrity_failure"
		}
		return s.failV2(res, t, tokens, code, "The manifest blob could not be read or does not match its recorded digests.")
	}
	var goSum []byte
	for i := range b.Companions {
		c := &b.Companions[i]
		if c.Kind == "go_sum" && dirOf(c.Path) == dirOf(m.Path) && srcPathProblem(c.Path) == "" {
			if d, err := s.readVerified(c); err == nil {
				goSum = d
			} else {
				res.Warnings = append(res.Warnings, "The go.sum companion could not be verified; integrity_recorded is unset for this manifest.")
			}
		}
	}
	parsed := parseByKind(m.Kind, data, goSum)
	stamp := s.now().Format(timeLayout)
	req := firstRequirement(t, "inventory")
	bundleRef := ArtifactRef{Digest: ref.Digest, MediaType: ref.MediaType, Role: "bundle_manifest"}
	blobRef := ArtifactRef{Digest: m.Blob, MediaType: "text/plain; charset=utf-8", Role: "manifest_blob"}
	evN := 0
	addEvidence := func(kind, locator, observation string, subject Subject, art ArtifactRef, output string, details map[string]any) string {
		evN++
		id := fmt.Sprintf("%s.ev%d", t.TaskID, evN)
		res.Evidence = append(res.Evidence, EvidenceItem{EvidenceID: id, Dimension: "inventory", Kind: kind, Subject: subject,
			ArtifactRef: art, Locator: locator, Observation: observation,
			CollectionMethod: CollectionMethod{Tool: kind, ToolVersion: toolVersionV3, ArgvTemplate: []string{kind, "<bundle-manifest>"}, OutputArtifact: output},
			Scope:            "Static inventory of the pinned commit, read as git blobs from a bare repository; no code was executed.",
			Limitations: []string{"Declared or locked inventory only: does not establish that a package is installed, built, executed or has any advisory.",
				"The file describes its own resolution, not what a build would use."},
			ObservedAt: stamp, Details: details})
		return id
	}

	// Repository scope and the paths without an inventory task ride on the first task of the repository.
	maxEvidence := 900
	if b.EmitScope {
		addEvidence("repo_source_scope", "listing",
			fmt.Sprintf("Commit %s of %s was read as git blobs from a bare repository; %d manifests were selected and %d excluded by policy.", b.Commit, b.Repo, b.SelectedManifestCount, b.ExcludedByPolicyCount),
			Subject{Module: b.Repo, Version: b.Commit}, bundleRef, ref.Digest, map[string]any{
				"repo": b.Repo, "commit": b.Commit, "tree": b.Tree, "fetch_method": "git_bare_no_checkout",
				"source_capture_set_id": b.SourceCaptureSetID, "listing_digest": b.ListingDigest,
				"selected_manifest_count": b.SelectedManifestCount, "excluded_by_policy_count": b.ExcludedByPolicyCount,
				"execution": "none"})
		for _, f := range b.Extras {
			if len(res.Evidence) >= maxEvidence {
				res.Warnings = append(res.Warnings, "Further manifest_status entries were not emitted: output limit.")
				res.MissingEvidence = append(res.MissingEvidence, MissingEvidence{RequirementID: req.RequirementID, Dimension: "inventory",
					Reason: "output_limit", Detail: "manifest_status entries beyond the evidence cap were not emitted."})
				break
			}
			shown := f.Path
			if srcPathProblem(shown) != "" {
				shown = "rejected-path-" + contentSHA256([]byte(f.Path))[:16]
			}
			status, covered, reason := statusFor(f, b.Siblings)
			var cov any
			if covered != "" {
				cov = covered
			}
			addEvidence("manifest_status", shown, fmt.Sprintf("%s: %s.", shown, status), Subject{Module: shown, Version: nonEmpty(f.GitBlob)},
				bundleRef, ref.Digest, map[string]any{"path": shown, "kind": f.Kind, "status": status, "covered_by": cov, "reason": reason})
		}
	}

	finish := func(status, summary string) *Message { return s.finishV2(res, tokens, status, summary) }
	switch parsed.Status {
	case "malformed", "unsupported", "too_large":
		reasons := map[string]string{"malformed": "manifest_malformed", "unsupported": "manifest_unsupported", "too_large": "manifest_too_large"}
		addEvidence("manifest_status", m.Path, fmt.Sprintf("%s: %s (%s).", m.Path, parsed.Status, parsed.Reason), Subject{Module: m.Path, Version: m.GitBlob},
			blobRef, ref.Digest, map[string]any{"path": m.Path, "kind": m.Kind, "status": parsed.Status, "covered_by": nil, "reason": parsed.Reason})
		res.MissingEvidence = append(res.MissingEvidence, MissingEvidence{RequirementID: req.RequirementID, Dimension: "inventory",
			Reason: reasons[parsed.Status], Detail: m.Path + ": " + parsed.Reason})
		return finish("partial", fmt.Sprintf("Partial: %s is %s; no occurrences recorded.", m.Path, parsed.Status))
	}

	table, err := buildOccTable(b.Repo, b.Commit, m.Path, m.Kind, parsed.Rows)
	if err != nil {
		res.MissingEvidence = append(res.MissingEvidence, MissingEvidence{RequirementID: req.RequirementID, Dimension: "inventory",
			Reason: "output_limit", Detail: m.Path + ": the occurrence table exceeds the artifact limit."})
		addEvidence("manifest_status", m.Path, m.Path+": table too large.", Subject{Module: m.Path, Version: m.GitBlob}, blobRef, ref.Digest,
			map[string]any{"path": m.Path, "kind": m.Kind, "status": "too_large", "covered_by": nil, "reason": "occurrence table exceeds the limit"})
		return finish("partial", "Partial: the occurrence table was too large.")
	}
	tableDigest, err := s.addProduced(res, t, table, "application/json", "occurrence_table", serviceID+"/"+opRepoInventory, m.Blob)
	if err != nil {
		return s.failV2(res, t, tokens, "output_too_large", "The occurrence table exceeds the artifact budget.")
	}
	var formatVersion any
	if parsed.FormatVersion != nil {
		formatVersion = *parsed.FormatVersion
	}
	parserName := map[string]string{"go_mod": "gomod", "npm_lock": "npm_lock", "pnpm_lock": "pnpm_lock", "uv_lock": "uv_lock", "package_json": "package_json"}[m.Kind]
	invID := addEvidence("manifest_inventory", m.Path,
		fmt.Sprintf("%d occurrence(s) recorded from %s (%s).", len(parsed.Rows), m.Path, parsed.Status),
		Subject{Module: m.Path, Version: m.GitBlob}, blobRef, tableDigest, map[string]any{
			"path": m.Path, "kind": m.Kind, "git_blob": m.GitBlob, "sha256": m.SHA256, "bytes": m.Bytes,
			"parser": map[string]any{"name": parserName, "version": parserVersion}, "status": parsed.Status,
			"occurrence_count": len(parsed.Rows), "table_artifact": tableDigest, "table_digest": tableDigest,
			"unparsed_constructs": parsed.unparsedList(), "lock_format_version": formatVersion})

	// Companions and covered siblings: manifest_status evidence, never a silent skip.
	for i := range b.Companions {
		c := b.Companions[i]
		if c.Kind != "go_sum" || dirOf(c.Path) != dirOf(m.Path) || srcPathProblem(c.Path) != "" {
			continue
		}
		addEvidence("manifest_status", c.Path, c.Path+": recognized_not_inventoried.", Subject{Module: c.Path, Version: nonEmpty(c.GitBlob)}, bundleRef, ref.Digest,
			map[string]any{"path": c.Path, "kind": c.Kind, "status": "recognized_not_inventoried", "covered_by": m.Path,
				"reason": "go.sum is read only as the companion of its go.mod"})
	}
	if len(parsed.CoveredDirs) > 0 {
		covered := map[string]bool{}
		for _, d := range parsed.CoveredDirs {
			covered[d] = true
		}
		lockDir := dirOf(m.Path)
		want := map[string]string{"npm_lock": "package_json", "pnpm_lock": "package_json", "uv_lock": "pyproject"}[m.Kind]
		sort.Slice(b.Siblings, func(i, j int) bool { return b.Siblings[i].Path < b.Siblings[j].Path })
		for _, sib := range b.Siblings {
			if want == "" || sib.Kind != want || srcPathProblem(sib.Path) != "" || sib.Path == m.Path {
				continue
			}
			sd := dirOf(sib.Path)
			rel, ok := sd, true
			if lockDir != "" {
				if sd == lockDir {
					rel = ""
				} else if strings.HasPrefix(sd, lockDir+"/") {
					rel = strings.TrimPrefix(sd, lockDir+"/")
				} else {
					ok = false
				}
			}
			if !ok || !covered[rel] {
				continue
			}
			if len(res.Evidence) >= maxEvidence {
				res.MissingEvidence = append(res.MissingEvidence, MissingEvidence{RequirementID: req.RequirementID, Dimension: "inventory",
					Reason: "output_limit", Detail: "covered_by_lock entries beyond the evidence cap were not emitted."})
				break
			}
			addEvidence("manifest_status", sib.Path, sib.Path+": covered_by_lock.", Subject{Module: sib.Path, Version: nonEmpty(sib.GitBlob)}, bundleRef, ref.Digest,
				map[string]any{"path": sib.Path, "kind": sib.Kind, "status": "covered_by_lock", "covered_by": m.Path,
					"reason": "listed as a member/importer by the lock file"})
		}
	}

	unparsedTotal := 0
	for _, n := range parsed.Unparsed {
		unparsedTotal += n
	}
	claimStatus, expl := "supported", "Supported by manifest_inventory evidence "+invID+": the manifest was fully parsed with no unrecognized construct."
	if parsed.Status != "parsed" || unparsedTotal > 0 {
		claimStatus, expl = "unknown", "The manifest was only partially parsed; recovered occurrences are recorded but the inventory is not asserted complete."
	}
	res.Claims = append(res.Claims, Claim{ClaimID: t.TaskID + ".cl1", Type: "manifest_inventory_recorded", Dimension: "inventory",
		Proposition: fmt.Sprintf("%s at the pinned commit records %d occurrence(s).", m.Path, len(parsed.Rows)),
		EvidenceIDs: []string{invID}, Status: claimStatus, Explanation: expl})
	if m.Kind == "package_json" {
		res.MissingEvidence = append(res.MissingEvidence, MissingEvidence{RequirementID: req.RequirementID, Dimension: "inventory",
			Reason: "lock_absent", Detail: m.Path + ": no lock file; declared specifiers only, never queried."})
	}
	if claimStatus != "supported" {
		reason := "manifest_unsupported"
		if parsed.Unparsed["output_limit_rows"] > 0 {
			reason = "output_limit"
		}
		class := make([]string, 0, len(parsed.Unparsed))
		for k, n := range parsed.Unparsed {
			class = append(class, fmt.Sprintf("%s:%d", k, n))
		}
		sort.Strings(class)
		if m.Kind != "package_json" || unparsedTotal > 0 {
			res.MissingEvidence = append(res.MissingEvidence, MissingEvidence{RequirementID: req.RequirementID, Dimension: "inventory",
				Reason: reason, Detail: m.Path + ": unrecognized constructs " + strings.Join(class, ",")})
		}
	}
	if len(res.MissingEvidence) > 0 {
		return finish("partial", fmt.Sprintf("Partial: %d occurrence(s) from %s; %d gap(s) left unknown.", len(parsed.Rows), m.Path, len(res.MissingEvidence)))
	}
	return finish("complete", fmt.Sprintf("Complete: %d occurrence(s) from %s.", len(parsed.Rows), m.Path))
}

// nonEmpty keeps the evidence subject version a valid non-empty string.
func nonEmpty(s string) string {
	if s == "" {
		return "unrecorded"
	}
	return s
}
