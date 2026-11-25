package main

// govulncheck_source execution (I2-REQ-06): pinned binary, captured database, sandbox, no network.

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const opVuln = "govulncheck_source"

func init() {
	registerV2(opVuln, "call_path", vulnHandler)
	// Contract 3.6: package-level findings are code_presence evidence, module-level ones inventory.
	v2EmittedDims["code_presence"] = true
}

type vulnBundle struct {
	Kind         string `json:"kind"`
	CaptureSetID string `json:"capture_set_id"`
	DBURL        string `json:"db_url"`
	Files        []struct {
		Path   string `json:"path"`
		Digest string `json:"digest"`
	} `json:"files"`
}

type toolProvenance struct {
	GoVersion   string `json:"go_version"`
	Govulncheck struct {
		Version   string     `json:"version"`
		BuildDeps [][]string `json:"build_deps"`
	} `json:"govulncheck"`
}

func gunzipLimited(b []byte, max int64) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	out, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil || int64(len(out)) > max {
		return nil, fmt.Errorf("decompressed size exceeds %d bytes", max)
	}
	return out, nil
}

// materializeDB rebuilds a file:// database directory from captured blobs. `*.json.gz` files are
// decompressed because govulncheck's file source reads plain JSON (its HTTP source reads gzip).
func (s *Server) materializeDB(b *vulnBundle, dir string) error {
	total := 0
	for _, f := range b.Files {
		if strings.Contains(f.Path, "..") || strings.HasPrefix(f.Path, "/") {
			return fmt.Errorf("unsafe database path %q", f.Path)
		}
		data, err := s.store.ReadMax(f.Digest, maxBundleBytes)
		if err != nil {
			return err
		}
		rel := f.Path
		if strings.HasSuffix(rel, ".json.gz") {
			if data, err = gunzipLimited(data, 32<<20); err != nil {
				return err
			}
			rel = strings.TrimSuffix(rel, ".gz")
		}
		if total += len(data); total > 64<<20 {
			return fmt.Errorf("database exceeds 64 MiB")
		}
		dest := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(dest, data, 0o644); err != nil {
			return err
		}
	}
	return nil
}

// toolIdentity compares `go version -m <binary>` with the provenance (module sums, not the binary hash).
func toolIdentity(ctx context.Context, w *Worker, env []string, dir, bin string, want [][]string, deadline time.Time) error {
	r := w.sandbox.Run(ctx, []string{w.goBin, "version", "-m", bin}, dir, env, limList, deadline)
	if r.Err != nil || r.Exit != 0 {
		return fmt.Errorf("go version -m failed")
	}
	var got [][]string
	for _, line := range strings.Split(string(r.Stdout), "\n") {
		if strings.HasPrefix(line, "\tdep\t") || strings.HasPrefix(line, "\tmod\t") {
			f := strings.Split(line, "\t")
			if len(f) >= 4 {
				got = append(got, f[1:4])
			}
		}
	}
	if len(got) != len(want) {
		return fmt.Errorf("build dependency list differs")
	}
	for i := range got {
		if strings.Join(got[i], " ") != strings.Join(want[i], " ") {
			return fmt.Errorf("build dependency %s differs", got[i][1])
		}
	}
	return nil
}

func vulnHandler(s *Server, ctx context.Context, t *TaskRequest, input *ArtifactRef, jobDeadline time.Time, tokens []Part) *Message {
	res := s.newV2Result(t, opVuln)
	unsupportedRequirements(res, t, opVuln, "call_path")
	if *t.Budget.MaxWorkerJobs < 1 {
		return s.failV2(res, t, tokens, "budget_exhausted", "The task budget allows no worker job.")
	}
	dbRef, provRef := inputByRole(t, "vulndb_bundle_manifest"), inputByRole(t, "tool_provenance")
	if dbRef == nil || provRef == nil {
		return s.rejectV2(tokens, false, "invalid_request", "vulndb_bundle_manifest and tool_provenance inputs are required.", t.TaskID, t.RunID)
	}
	p, fail := s.prepareTree(ctx, t, jobDeadline, false)
	if fail != nil {
		if fail.rejectCode != "" {
			return s.rejectV2(tokens, false, fail.rejectCode, fail.rejectMsg, t.TaskID, t.RunID)
		}
		return s.failV2(res, t, tokens, fail.errCode, fail.errMsg)
	}
	defer p.cleanup()
	w := s.worker
	var bundle vulnBundle
	rawB, errB := s.store.ReadMax(dbRef.Digest, maxBundleBytes)
	var prov toolProvenance
	rawP, errP := s.store.ReadMax(provRef.Digest, 1<<20)
	switch {
	case errB != nil:
		return s.failV2(res, t, tokens, "artifact_not_found", "The database bundle manifest could not be read.")
	case errP != nil:
		return s.failV2(res, t, tokens, "artifact_not_found", "The tool provenance could not be read.")
	case json.Unmarshal(rawB, &bundle) != nil || bundle.Kind != "vulndb" || json.Unmarshal(rawP, &prov) != nil:
		return s.failV2(res, t, tokens, "artifact_integrity_failure", "The bundle or provenance is malformed.")
	case bundle.CaptureSetID != t.CaptureSetID:
		return s.rejectV2(tokens, false, "capture_mismatch", "The bundle's capture_set_id differs from the task's.", t.TaskID, t.RunID)
	case prov.GoVersion != w.goVersion:
		return s.failV2(res, t, tokens, "toolchain_mismatch", fmt.Sprintf("The provenance expects %s; found %s.", prov.GoVersion, w.goVersion))
	}
	bin := filepath.Join(w.toolDir, "govulncheck")
	if _, err := os.Stat(bin); w.toolDir == "" || err != nil {
		return s.failV2(res, t, tokens, "module_unavailable", "The pinned govulncheck binary is not available.")
	}
	env := jobEnv(w, p.ws)
	if err := toolIdentity(ctx, w, env, p.tree, bin, prov.Govulncheck.BuildDeps, jobDeadline); err != nil {
		return s.failV2(res, t, tokens, "toolchain_mismatch", "The govulncheck binary does not match the provenance: "+err.Error()+".")
	}
	dbDir := filepath.Join(p.ws, "db")
	if err := s.materializeDB(&bundle, dbDir); err != nil {
		return s.failV2(res, t, tokens, "capture_unavailable", "The database capture could not be rebuilt: "+err.Error()+".")
	}
	lim := limVuln
	r := w.sandbox.Run(ctx, []string{bin, "-mode=source", "-format=json", "-db", "file://" + dbDir, govulncheckPattern}, p.tree, env, lim, jobDeadline)
	norm := newNormalizer(pathRule{"file://" + dbDir, "file://<capture-db>"}, pathRule{p.ws, "<TMP>"},
		pathRule{w.goroot, "<GOROOT>"}, pathRule{w.modcache, "<GOMODCACHE>"})
	stream := norm.apply(r.Stdout)
	stderr := norm.apply(r.Stderr)
	inputRef := ArtifactRef{Digest: input.Digest, MediaType: input.MediaType, Role: "source_manifest"}

	artifact := map[string]any{"schema": "opentrace.analyzer_stream/1", "exit": r.Exit, "stderr_tail": tail(string(stderr), 2000),
		"path_normalization": norm.summary(), "stream": string(stream)}
	if r.Err != nil || r.TimedOut || r.Overflow {
		why := "the analyzer could not run"
		code := "analyzer_error"
		switch {
		case r.TimedOut:
			code, why = "worker_timeout", "the analyzer exceeded its time limit"
		case r.Overflow:
			code, why = "output_too_large", "the analyzer output exceeded the cap"
		}
		_, _ = s.addProduced(res, t, canonicalJSON(artifact), "application/json", "analyzer_stream", serviceID+"/"+opVuln, input.Digest)
		return s.failV2(res, t, tokens, code, "No analysis: "+why+".")
	}
	st, parseErr := parseVulnStream(stream)
	if err := streamComplete(st, parseErr, r.Exit); err != nil {
		_, _ = s.addProduced(res, t, canonicalJSON(artifact), "application/json", "analyzer_stream", serviceID+"/"+opVuln, input.Digest)
		detail := err.Error()
		if tl := strings.TrimSpace(tail(string(stderr), 300)); tl != "" {
			detail += " (" + tl + ")"
		}
		return s.failV2(res, t, tokens, "analyzer_error", "The analysis did not complete, so nothing is established: "+detail+".")
	}
	if st.Config.GoVersion != w.goVersion || st.Config.ScannerVersion != prov.Govulncheck.Version {
		_, _ = s.addProduced(res, t, canonicalJSON(artifact), "application/json", "analyzer_stream", serviceID+"/"+opVuln, input.Digest)
		return s.failV2(res, t, tokens, "toolchain_mismatch", "The stream's scanner or Go version differs from the provenance.")
	}
	digest, err := s.addProduced(res, t, canonicalJSON(artifact), "application/json", "analyzer_stream", serviceID+"/"+opVuln, input.Digest)
	if err != nil {
		return s.failV2(res, t, tokens, "output_too_large", "The analyzer stream exceeds the artifact budget.")
	}
	buildVulnEvidence(res, t, st, inputRef, digest, bundle.DBURL+" (captured)", s.now().Format(timeLayout),
		"govulncheck@"+st.Config.ScannerVersion, "linux", "amd64")
	paths := 0
	for _, e := range res.Evidence {
		if e.Kind == "vuln_call_path" {
			paths++
		}
	}
	return s.finishV2(res, tokens, "complete", fmt.Sprintf("Complete: govulncheck analysis finished; %d call-path item(s), %d advisor(ies) examined.", paths, len(st.OSVIDs)))
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}
