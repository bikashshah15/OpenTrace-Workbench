package main

// Major 3.0 handling (I3-REQ-02). A major 3 payload reaches this file only with the contract token
// "3.0"; everything else is handled by the 1.0/2.0 code paths, which are unchanged in behavior.
// Operations register from init() in their own file, so the advertised capability always equals what
// is implemented.

import (
	"context"
	"fmt"
	"sort"
	"time"
)

const (
	contractV3          = "3.0"
	capabilityVersionV3 = "3.0"
	buildScopeV3        = "static inventory; no build; no code execution"
	toolVersionV3       = "evidence-specialist-b/i3"
)

// v3Handler processes one major 3 operation. The job deadline already has the response reserve subtracted.
type v3Handler func(s *Server, ctx context.Context, t *TaskRequest, jobDeadline time.Time, tokens []Part) *Message

var (
	v3Handlers      = map[string]v3Handler{}
	v3OperationDims = map[string]string{}
)

func registerV3(op, dimension string, h v3Handler) {
	v3OperationDims[op] = dimension
	v3Handlers[op] = h
}

func capabilityV3(requestID string) CapabilityResponse {
	var ops []string
	for op := range v3OperationDims {
		ops = append(ops, op)
	}
	sort.Strings(ops)
	return CapabilityResponse{
		Kind: "capability_response", SchemaVersion: contractV3, RequestID: requestID,
		ServiceID: serviceID, Implementation: "go", CapabilityVersion: capabilityVersionV3,
		ContractVersions: []string{contractV3}, Operations: ops, Dimensions: []string{"inventory"},
		Languages: []string{"go", "multi", "python", "typescript"},
		Limits: Limits{ModelCalls: 0, NonLoopbackNetwork: 0, MaxWorkerJobsPerTask: 1, WorkerTimeoutS: 30,
			DefaultTaskDeadlineS: defaultDeadlineS, MaxProducedArtifactBytes: maxProducedBytesV2,
			OperationLimits: map[string]any{
				"repo_inventory":      map[string]any{"wall_s": 30, "deadline_s": 60},
				"osv_inventory_match": map[string]any{"deadline_s": 60},
				"github_sbom_import":  map[string]any{"wall_s": 20, "deadline_s": 60},
			}},
	}
}

func (s *Server) rejectV3(tokens []Part, control bool, code, message, taskID, runID string) *Message {
	r := newRejection(taskID, runID, code, message)
	r.SchemaVersion = contractV3
	return s.reject(tokens, control, r)
}

// handleV3 serves a major 3 request that carried a valid contract token.
func (s *Server) handleV3(ctx context.Context, msg *Message, raw []byte, kind, requestID string, tokens []Part) *Message {
	switch {
	case kind == "capability_request" && msg.IsControl():
		if !identifierRE.MatchString(requestID) {
			return s.rejectV3(tokens, true, "invalid_request", "request_id must be an identifier.", "", "")
		}
		reply, _ := replyStructured(capabilityV3(requestID), true, tokens,
			"Capability 3.0: "+fmt.Sprint(len(v3OperationDims))+" static inventory operations; contract 3.0; loopback development mode.")
		return reply
	case kind == "task_request" && !msg.IsControl():
		return s.handleTaskV3(ctx, raw, tokens)
	default:
		return s.rejectV3(tokens, msg.IsControl(), "unsupported_kind", "Unsupported payload kind or MessageType combination.", "", "")
	}
}

func (s *Server) handleTaskV3(ctx context.Context, raw []byte, tokens []Part) *Message {
	t, err := decodeTask(raw)
	if err != nil {
		return s.rejectV3(tokens, false, "invalid_request", err.Error()+".", "", "")
	}
	rej := func(code, message string) *Message {
		return s.rejectV3(tokens, false, code, message, t.TaskID, t.RunID)
	}
	now := s.now()
	deadline, err := parseTime(t.Deadline)
	if err != nil {
		return rej("invalid_request", "deadline is invalid.")
	}
	if !now.Before(deadline) {
		return rej("deadline_exceeded", "The task deadline had passed on receipt.")
	}
	if deadline.Sub(now) > maxTaskDeadlineS*time.Second {
		return rej("invalid_request", fmt.Sprintf("deadline is more than %d s after receipt.", maxTaskDeadlineS))
	}
	if t.CapabilityVersion != capabilityVersionV3 {
		return rej("unsupported_capability_version", "capability_version must be "+capabilityVersionV3+".")
	}
	if len(t.Operations) != 1 {
		return rej("invalid_request", "A 3.0 task names exactly one operation.")
	}
	op := t.Operations[0]
	h := v3Handlers[op]
	if _, ok := v3OperationDims[op]; !ok || h == nil {
		return rej("operation_not_supported", fmt.Sprintf("Operation %s is not in this specialist's 3.0 capability.", op))
	}
	if t.Context.BuildScope != buildScopeV3 {
		return rej("context_mismatch", "build_scope must be the exact static-inventory scope string.")
	}
	return s.runV3(h, ctx, t, deadline.Add(-responseReserve), tokens, op)
}

// runV3 invokes a handler and turns a panic into a failed result: a hostile input must never crash B.
func (s *Server) runV3(h v3Handler, ctx context.Context, t *TaskRequest, jobDeadline time.Time, tokens []Part, op string) (msg *Message) {
	defer func() {
		if r := recover(); r != nil {
			msg = s.failV2(s.newV3Result(t, op), t, tokens, "worker_failed", "The operation hit an internal error and returned no evidence.")
		}
	}()
	return h(s, ctx, t, jobDeadline, tokens)
}

func (s *Server) newV3Result(t *TaskRequest, op string) *Result {
	return &Result{Kind: "result", SchemaVersion: contractV3, TaskID: t.TaskID, RunID: t.RunID, Context: t.Context,
		Producer: Producer{ServiceID: serviceID, Implementation: "go", CapabilityVersion: capabilityVersionV3,
			OperationsUsed: []string{op}, DimensionsUsed: []string{}},
		Evidence: []EvidenceItem{}, Claims: []Claim{}, Artifacts: []ProducedArtifact{},
		MissingEvidence: []MissingEvidence{}, Warnings: []string{}, Errors: []DomainError{},
		CaptureSetID: t.CaptureSetID}
}
