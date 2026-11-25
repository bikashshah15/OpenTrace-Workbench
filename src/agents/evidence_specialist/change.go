package main

// change_validate (I2-REQ-07): one variant (baseline, or baseline plus one patch) is validated by
// the frozen required checks inside the sandbox. Comparison across variants is the core's job; the
// same check_spec_digest in both calls is what makes the checks identical.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"
)

const opChange = "change_validate"

func init() { registerV2(opChange, "change_validation", changeHandler) }

type checkOutcome struct {
	ID, Outcome string
	Required    bool
	Exit        int
	DurationMS  int64
	MaxRSSKB    int64
	Passed      int
	Failed      int
	FailedTests []string
	Stdout      string
	Stderr      string
	Truncated   bool
	Argv        []string
}

func environmentRecord() map[string]any {
	return map[string]any{
		"go_version": pinnedGoVersion, "goos": "linux", "goarch": "amd64", "cgo": false,
		"goflags": "-mod=readonly", "goproxy": "off", "gotoolchain": "local", "gosumdb": "off",
		"sandbox": "unshare --net + prlimit",
		"limits": map[string]any{
			"git_apply": "30s/30s/2GiB", "modverify": "60s/60s/6GiB", "build": "120s/120s/6GiB", "vet": "120s/120s/6GiB",
			"test": "120s/120s/6GiB", "modlist": "30s/30s/4GiB", "govulncheck": "180s/180s/6GiB",
			"output_cap_bytes": 1 << 20, "workspace_bytes": 64 << 20},
	}
}

func canonicalDigest(v any) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	return sha256Digest(buf.Bytes())
}

func truncate(b []byte, max int) (string, bool) {
	if len(b) <= max {
		return string(b), false
	}
	return string(b[:max]), true
}

// classify maps a command result to a check outcome (contract section 3.3 "pass means").
func classify(id string, res cmdResult) (outcome string, passed, failed int, failedTests []string) {
	switch {
	case res.Err != nil:
		return "error", 0, 0, nil
	case res.TimedOut:
		return "timeout", 0, 0, nil
	case res.Overflow:
		return "error", 0, 0, nil
	case res.Exit != 0:
		outcome = "failed"
	default:
		outcome = "passed"
	}
	switch id {
	case "modverify":
		if outcome == "passed" && !bytes.Contains(res.Stdout, []byte("all modules verified")) {
			outcome = "failed"
		}
	case "test":
		sawTarget := false
		for _, line := range bytes.Split(res.Stdout, []byte("\n")) {
			if len(bytes.TrimSpace(line)) == 0 {
				continue
			}
			var ev struct{ Action, Test string }
			if json.Unmarshal(line, &ev) != nil {
				if outcome == "passed" {
					outcome = "failed" // an unparsable -json stream is not a pass
				}
				continue
			}
			if ev.Test != "" && ev.Action == "pass" {
				passed++
				if ev.Test == "TestNegotiate" {
					sawTarget = true
				}
			}
			if ev.Test != "" && ev.Action == "fail" {
				failed++
				failedTests = append(failedTests, ev.Test)
			}
		}
		if outcome == "passed" && !sawTarget {
			outcome = "failed"
		}
	}
	return outcome, passed, failed, failedTests
}

func changeHandler(s *Server, ctx context.Context, t *TaskRequest, input *ArtifactRef, jobDeadline time.Time, tokens []Part) *Message {
	res := s.newV2Result(t, opChange)
	unsupportedRequirements(res, t, opChange, "change_validation")
	if *t.Budget.MaxWorkerJobs < 1 {
		return s.failV2(res, t, tokens, "budget_exhausted", "The task budget allows no worker job.")
	}
	p, fail := s.prepareTree(ctx, t, jobDeadline, true)
	if fail != nil {
		if fail.rejectCode != "" {
			return s.rejectV2(tokens, false, fail.rejectCode, fail.rejectMsg, t.TaskID, t.RunID)
		}
		return s.failV2(res, t, tokens, fail.errCode, fail.errMsg)
	}
	defer p.cleanup()
	w := s.worker
	env := jobEnv(w, p.ws)
	postApply := snapshotTree(p.tree)
	unexpected := unexpectedChanges(p.baseSHA, p.patchFiles, postApply)

	var outcomes []checkOutcome
	for _, c := range p.spec.Checks {
		lim := checkLimits[c.CheckID]
		r := w.sandbox.Run(ctx, c.Argv, p.tree, env, lim, jobDeadline)
		outcome, passed, failed, failedTests := classify(c.CheckID, r)
		so, t1 := truncate(p.norm.apply(r.Stdout), 64<<10)
		se, t2 := truncate(p.norm.apply(r.Stderr), 64<<10)
		outcomes = append(outcomes, checkOutcome{ID: c.CheckID, Outcome: outcome, Required: c.Required, Exit: r.Exit,
			DurationMS: r.Duration.Milliseconds(), MaxRSSKB: r.MaxRSSKB, Passed: passed, Failed: failed, FailedTests: failedTests,
			Stdout: so, Stderr: se, Truncated: t1 || t2, Argv: c.Argv})
	}
	// Files the checks themselves changed are reported, never ignored.
	after := snapshotTree(p.tree)
	for path, sum := range after {
		if prev, ok := postApply[path]; !ok {
			unexpected = append(unexpected, "created_by_checks:"+path)
		} else if prev != sum {
			unexpected = append(unexpected, "modified_by_checks:"+path)
		}
	}

	out := map[string]any{"schema": "opentrace.check_output/1", "checks": map[string]any{}}
	for _, o := range outcomes {
		out["checks"].(map[string]any)[o.ID] = map[string]any{"argv": o.Argv, "exit": o.Exit, "stdout": o.Stdout,
			"stderr": o.Stderr, "truncated": o.Truncated}
	}
	specRef := inputByRole(t, "check_spec")
	outDigest, err := s.addProduced(res, t, canonicalJSON(out), "application/json", "check_output", serviceID+"/"+opChange, input.Digest)
	if err != nil {
		return s.failV2(res, t, tokens, "output_too_large", "The check output exceeds the artifact budget.")
	}
	variant, version := "baseline", "baseline"
	if p.patchDigest != "" {
		variant, version = "candidate", p.patchDigest
	}
	stamp := s.now().Format(timeLayout)
	srcRef := ArtifactRef{Digest: input.Digest, MediaType: input.MediaType, Role: "source_manifest"}
	var checkIDs []string
	for i, o := range outcomes {
		evID := fmt.Sprintf("%s.ck%d", t.TaskID, i+1)
		checkIDs = append(checkIDs, evID)
		details := map[string]any{"variant": variant, "check_id": o.ID, "argv_template": o.Argv, "required": o.Required,
			"outcome": o.Outcome, "exit_code": o.Exit, "duration_ms": o.DurationMS, "output_artifact": outDigest, "max_rss_kb": o.MaxRSSKB}
		if o.ID == "test" {
			details["tests_passed"], details["tests_failed"] = o.Passed, o.Failed
			if o.FailedTests == nil {
				o.FailedTests = []string{}
			}
			details["failed_tests"] = o.FailedTests
		}
		obs := fmt.Sprintf("Check %s on the %s tree: %s (exit %d).", o.ID, variant, o.Outcome, o.Exit)
		res.Evidence = append(res.Evidence, EvidenceItem{EvidenceID: evID, Dimension: "change_validation", Kind: "check_result",
			Subject: Subject{Module: p.module, Version: version}, ArtifactRef: srcRef, Locator: "check#" + o.ID,
			Observation: obs, Scope: "Frozen required checks under the recorded environment, offline, in a network namespace.",
			Limitations: []string{"Passing named checks is not successful remediation in every environment.",
				"A failed or timed-out check is a recorded outcome, not an inference about the cause."},
			CollectionMethod: CollectionMethod{Tool: "go", ToolVersion: w.goVersion, ArgvTemplate: o.Argv, OutputArtifact: outDigest},
			ObservedAt:       stamp, Details: details})
		ctype := "check_passed"
		if o.Outcome != "passed" {
			ctype = "check_failed"
		}
		res.Claims = append(res.Claims, Claim{ClaimID: fmt.Sprintf("%s.cl%d", t.TaskID, i+1), Type: ctype, Dimension: "change_validation",
			Proposition: obs, EvidenceIDs: []string{evID}, Status: "supported",
			Explanation: "Supported by the recorded check result " + evID + "; it states the outcome of this check only.",
			CheckID:     o.ID, Variant: variant})
	}
	env2 := environmentRecord()
	var candID, patchDigest *string
	if p.patchDigest != "" {
		candID, patchDigest = &p.patchDigest, &p.patchDigest
	}
	pf := p.patchFiles
	if pf == nil {
		pf = []string{}
	}
	res.ChangeResult = &ChangeResult{Variant: variant, BaselineRevision: t.Context.RequestedRevision, CandidateID: candID,
		PatchDigest: patchDigest, PatchFiles: pf, UnexpectedChanges: dedupe(unexpected), OracleFilesUnchanged: true,
		Environment: env2, EnvironmentDigest: canonicalDigest(env2), CheckSpecDigest: specRef.Digest, Checks: checkIDs,
		ComparisonLimits: []string{"Passed this captured validation suite only; not universal remediation or deployment readiness.",
			"Single OS/arch (" + w.goVersion + " linux/amd64), network-less, first-party code."}}
	res.Warnings = append(res.Warnings, "path normalization applied: "+fmt.Sprint(p.norm.summary()))
	failedRequired := 0
	for _, o := range outcomes {
		if o.Required && o.Outcome != "passed" {
			failedRequired++
		}
	}
	return s.finishV2(res, tokens, "complete", fmt.Sprintf("Complete: %d checks run on the %s tree; %d required check(s) not passed.", len(outcomes), variant, failedRequired))
}

func dedupe(in []string) []string {
	seen, out := map[string]bool{}, []string{}
	for _, v := range in {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
