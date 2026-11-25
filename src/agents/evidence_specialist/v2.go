package main

// Major 2.0 handling (I2-REQ-02). A major 2 payload reaches this file only with the contract
// token; everything else is handled by the 1.0 code path, which is unchanged in behavior.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

const capabilityVersionV2 = "2.0"

// v2Handler processes one major 2 operation. The job deadline already has the response reserve
// subtracted (I2-REQ-01 item 8).
type v2Handler func(s *Server, ctx context.Context, t *TaskRequest, input *ArtifactRef, jobDeadline time.Time, tokens []Part) *Message

var (
	v2Handlers      = map[string]v2Handler{}
	v2OperationDims = map[string]string{opGoModInventory: "inventory"}
	// v2EmittedDims are dimensions an operation emits evidence in besides its requested one. They are
	// advertised so the core's capability-scope rule accepts exactly what B produces.
	v2EmittedDims = map[string]bool{}
)

// registerV2 adds an operation to the 2.0 capability. Operations register from init() in their
// own file, so the advertised capability always equals what is implemented.
func registerV2(op, dimension string, h v2Handler) {
	v2OperationDims[op] = dimension
	v2Handlers[op] = h
}

// operationLimits are the section 5 values of the I2 contract, advertised per operation.
func operationLimits() map[string]any {
	return map[string]any{
		"go_mod_inventory":   map[string]any{"wall_s": 10, "deadline_s": 30},
		"osv_advisory_match": map[string]any{"deadline_s": 30},
		"govulncheck_source": map[string]any{"wall_s": 180, "cpu_s": 180, "address_space_bytes": 6 << 30, "deadline_s": 240},
		"change_validate": map[string]any{"deadline_s": 600, "commands": map[string]any{
			"git_apply": 30, "modverify": 60, "build": 120, "vet": 120, "test": 120, "modlist": 30}},
	}
}

func capabilityV2(requestID string) CapabilityResponse {
	var ops []string
	dimSet := map[string]bool{}
	for d := range v2EmittedDims {
		dimSet[d] = true
	}
	for op, dim := range v2OperationDims {
		ops = append(ops, op)
		dimSet[dim] = true
	}
	sort.Strings(ops)
	var dims []string
	for d := range dimSet {
		dims = append(dims, d)
	}
	sort.Strings(dims)
	return CapabilityResponse{
		Kind: "capability_response", SchemaVersion: contractV2, RequestID: requestID,
		ServiceID: serviceID, Implementation: "go", CapabilityVersion: capabilityVersionV2,
		ContractVersions: []string{contractV2}, Operations: ops, Dimensions: dims, Languages: []string{"go"},
		Limits: Limits{ModelCalls: 0, NonLoopbackNetwork: 0, MaxWorkerJobsPerTask: 1, WorkerTimeoutS: 180,
			DefaultTaskDeadlineS: defaultDeadlineS, MaxProducedArtifactBytes: maxProducedBytesV2,
			OperationLimits: operationLimits()},
	}
}

func (s *Server) rejectV2(tokens []Part, control bool, code, message, taskID, runID string) *Message {
	r := newRejection(taskID, runID, code, message)
	r.SchemaVersion = contractV2
	return s.reject(tokens, control, r)
}

// handleV2 serves a major 2 request that carried a valid contract token.
func (s *Server) handleV2(ctx context.Context, msg *Message, raw json.RawMessage, kind, requestID string, tokens []Part) *Message {
	switch {
	case kind == "capability_request" && msg.IsControl():
		if !identifierRE.MatchString(requestID) {
			return s.rejectV2(tokens, true, "invalid_request", "request_id must be an identifier.", "", "")
		}
		reply, _ := replyStructured(capabilityV2(requestID), true, tokens,
			"Capability 2.0: "+fmt.Sprint(len(v2OperationDims))+" operations (go); contract 2.0; loopback development mode.")
		return reply
	case kind == "task_request" && !msg.IsControl():
		return s.handleTask(ctx, raw, tokens, contractV2)
	default:
		return s.rejectV2(tokens, msg.IsControl(), "unsupported_kind", "Unsupported payload kind or MessageType combination.", "", "")
	}
}

// ChangeResult is the major 2.0 change_result object (filled by change_validate).
type ChangeResult struct {
	Variant              string         `json:"variant"`
	BaselineRevision     string         `json:"baseline_revision"`
	CandidateID          *string        `json:"candidate_id"`
	PatchDigest          *string        `json:"patch_digest"`
	PatchFiles           []string       `json:"patch_files"`
	UnexpectedChanges    []string       `json:"unexpected_changes"`
	OracleFilesUnchanged bool           `json:"oracle_files_unchanged"`
	Environment          map[string]any `json:"environment"`
	EnvironmentDigest    string         `json:"environment_digest"`
	CheckSpecDigest      string         `json:"check_spec_digest"`
	Checks               []string       `json:"checks"`
	ComparisonLimits     []string       `json:"comparison_limits"`
}

// ---- shared helpers for major 2.0 operations -------------------------------------------------

func (s *Server) newV2Result(t *TaskRequest, op string) *Result {
	return &Result{Kind: "result", SchemaVersion: contractV2, TaskID: t.TaskID, RunID: t.RunID, Context: t.Context,
		Producer: Producer{ServiceID: serviceID, Implementation: "go", CapabilityVersion: capabilityVersionV2,
			OperationsUsed: []string{op}, DimensionsUsed: []string{}},
		Evidence: []EvidenceItem{}, Claims: []Claim{}, Artifacts: []ProducedArtifact{},
		MissingEvidence: []MissingEvidence{}, Warnings: []string{}, Errors: []DomainError{},
		CaptureSetID: t.CaptureSetID}
}

func (s *Server) finishV2(res *Result, tokens []Part, status, summary string) *Message {
	res.Status = status
	res.CompletedAt = s.now().Format(timeLayout)
	dims := map[string]bool{}
	for _, e := range res.Evidence {
		dims[e.Dimension] = true
	}
	res.Producer.DimensionsUsed = res.Producer.DimensionsUsed[:0]
	for d := range dims {
		res.Producer.DimensionsUsed = append(res.Producer.DimensionsUsed, d)
	}
	sort.Strings(res.Producer.DimensionsUsed)
	reply, _ := replyStructured(res, false, tokens, summary)
	return reply
}

// failV2 records a failed result: the error, a worker_failed gap for every requirement, no claims.
func (s *Server) failV2(res *Result, t *TaskRequest, tokens []Part, code, message string) *Message {
	res.Errors = append(res.Errors, DomainError{Code: code, Message: message, Retryable: false})
	res.Evidence, res.Claims = []EvidenceItem{}, []Claim{}
	reason := "worker_failed"
	switch code {
	case "toolchain_mismatch", "sandbox_unavailable", "module_unavailable", "analyzer_error", "capture_unavailable":
		reason = code
	case "artifact_not_found", "artifact_integrity_failure":
		reason = "input_unavailable"
	}
	for _, req := range t.Requirements {
		res.MissingEvidence = append(res.MissingEvidence, MissingEvidence{RequirementID: req.RequirementID,
			Dimension: req.Dimension, Reason: reason, Detail: "No evidence: " + code + "."})
	}
	return s.finishV2(res, tokens, "failed", "Failed: "+code+"; no evidence returned.")
}

// addProduced appends a produced artifact (digest, base64 bytes) and returns its digest.
func (s *Server) addProduced(res *Result, t *TaskRequest, data []byte, mediaType, role, producer, sourceRef string) (string, error) {
	limit := *t.Budget.MaxProducedArtifactBytes
	if len(data) > limit || len(data) > maxProducedBytesV2 {
		return "", fmt.Errorf("output_too_large")
	}
	if len(res.Artifacts) >= 4 {
		return "", fmt.Errorf("too many produced artifacts")
	}
	sum := sha256.Sum256(data)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	res.Artifacts = append(res.Artifacts, ProducedArtifact{Digest: digest, MediaType: mediaType, Bytes: len(data),
		ContentB64: base64.StdEncoding.EncodeToString(data), Producer: producer, SourceRef: sourceRef,
		CapturedAt: s.now().Format(timeLayout), Role: role})
	return digest, nil
}

// inputByRole returns the first input with the given role.
func inputByRole(t *TaskRequest, role string) *ArtifactRef {
	for i := range t.Inputs {
		if t.Inputs[i].Role == role {
			return &t.Inputs[i]
		}
	}
	return nil
}

// firstRequirement returns the first requirement of the given dimension (or the first requirement).
func firstRequirement(t *TaskRequest, dimension string) Requirement {
	for _, r := range t.Requirements {
		if r.Dimension == dimension {
			return r
		}
	}
	return t.Requirements[0]
}

// unsupportedRequirements reports every requirement whose dimension this operation cannot establish.
func unsupportedRequirements(res *Result, t *TaskRequest, op, dimension string) bool {
	any := false
	for _, r := range t.Requirements {
		if r.Dimension != dimension {
			res.MissingEvidence = append(res.MissingEvidence, MissingEvidence{RequirementID: r.RequirementID,
				Dimension: r.Dimension, Reason: "unsupported_dimension",
				Detail: fmt.Sprintf("Operation %s establishes dimension %s only.", op, dimension)})
			any = true
		}
	}
	return any
}

func canonicalJSON(v any) []byte {
	b, _ := json.Marshal(v) // map keys are sorted by encoding/json
	return append(b, '\n')
}

func sha256Digest(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}
