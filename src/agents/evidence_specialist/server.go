package main

// ECMA-431 binding: POST /nlip, application/json. 200 for every NLIP response
// (including domain rejections); 400 with an NLIP text/english message for a
// non-JSON body or a missing/invalid required NLIP field.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const maxBodyBytes = 1 << 20

const acceptsText = "evidence-specialist-b accepts NLIP messages at POST /nlip: a control capability_request, " +
	"or a structured/json task_request (opentrace.evidence 1.x) for operation go_mod_inventory " +
	"(dimension inventory, language go) with inputs referenced by sha256 digest."

type Server struct {
	store  Store
	worker *Worker
	now    func() time.Time
}

func NewServer(storeRoot string, worker *Worker) *Server {
	return &Server{store: Store{root: storeRoot}, worker: worker, now: func() time.Time { return time.Now().UTC() }}
}

func writeNLIP(w http.ResponseWriter, status int, m *Message) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(m)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/nlip" {
		writeNLIP(w, http.StatusNotFound, textMessage("Not found; NLIP endpoint is POST /nlip."))
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeNLIP(w, http.StatusMethodNotAllowed, textMessage("Method not allowed; use POST /nlip."))
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		writeNLIP(w, http.StatusBadRequest, textMessage("Request body is unreadable or larger than 1 MiB."))
		return
	}
	msg, err := ParseMessage(body)
	if err != nil {
		writeNLIP(w, http.StatusBadRequest, textMessage("Invalid NLIP message: "+err.Error()+"."))
		return
	}
	writeNLIP(w, http.StatusOK, s.Handle(r.Context(), msg))
}

// Handle maps a valid NLIP message to its NLIP reply (always HTTP 200).
func (s *Server) Handle(ctx context.Context, msg *Message) *Message {
	tokens := msg.CorrelationTokens()
	raw, ok := msg.StructuredPayload()
	if !ok {
		if msg.Format == "text" {
			reply := textMessage(acceptsText)
			reply.Submessages = tokens
			return reply
		}
		return s.reject(tokens, msg.IsControl(), newRejection("", "", "unsupported_kind",
			"No structured/json domain payload; "+acceptsText))
	}
	var head struct {
		Kind          string `json:"kind"`
		SchemaVersion string `json:"schema_version"`
		TaskID        string `json:"task_id"`
		RunID         string `json:"run_id"`
		RequestID     string `json:"request_id"`
	}
	if err := json.Unmarshal(raw, &head); err != nil {
		return s.reject(tokens, msg.IsControl(), newRejection("", "", "invalid_request", "Domain payload is not a JSON object."))
	}
	major, valid := schemaMajor(head.SchemaVersion)
	if !valid {
		return s.reject(tokens, msg.IsControl(), newRejection(head.TaskID, head.RunID, "invalid_request", "schema_version is missing or malformed."))
	}
	if tok, version, ok := msg.ContractToken(); ok && !(major == 2 && version == contractV2) && !(major == 3 && version == contractV3) {
		// A contract token that disagrees with the payload (or names an unknown contract) is never
		// processed; the reply is a 1.0 rejection (I2-REQ-02).
		_ = tok
		return s.reject(tokens, msg.IsControl(), newRejection(head.TaskID, head.RunID, "unsupported_schema_version",
			"The contract token disagrees with the payload schema_version."))
	}
	if major == 2 {
		// Major 2 is processed only with the contract token (I2-REQ-02). Without a valid token the
		// reply is a 1.0 rejection, exactly as for any other unsupported major (I1 R2 stays valid).
		if tok, version, ok := msg.ContractToken(); ok && version == contractV2 {
			return s.handleV2(ctx, msg, raw, head.Kind, head.RequestID, append(append([]Part{}, tokens...), tok))
		}
		return s.reject(tokens, msg.IsControl(), newRejection(head.TaskID, head.RunID, "unsupported_schema_version",
			fmt.Sprintf("schema_version %s needs the %s contract token; this reply is a 1.0 rejection.", head.SchemaVersion, contractTokenSubformat)))
	}
	if major == 3 {
		// Major 3 is processed only with the "3.0" contract token (I3-REQ-02); the (major, token) pair must agree.
		if tok, version, ok := msg.ContractToken(); ok && version == contractV3 {
			return s.handleV3(ctx, msg, raw, head.Kind, head.RequestID, append(append([]Part{}, tokens...), tok))
		}
		return s.reject(tokens, msg.IsControl(), newRejection(head.TaskID, head.RunID, "unsupported_schema_version",
			fmt.Sprintf("schema_version %s needs the %s contract token; this reply is a 1.0 rejection.", head.SchemaVersion, contractTokenSubformat)))
	}
	if major != supportedMajor {
		return s.reject(tokens, msg.IsControl(), newRejection(head.TaskID, head.RunID, "unsupported_schema_version",
			fmt.Sprintf("schema_version %s is not supported; this specialist accepts 1.x.", head.SchemaVersion)))
	}
	switch {
	case head.Kind == "capability_request" && msg.IsControl():
		if !identifierRE.MatchString(head.RequestID) {
			return s.reject(tokens, true, newRejection("", "", "invalid_request", "request_id must be an identifier."))
		}
		reply, _ := replyStructured(capabilityFor(head.RequestID), true, tokens,
			"Capability: go_mod_inventory (inventory, go); contract 1.0; loopback development mode.")
		return reply
	case head.Kind == "task_request" && !msg.IsControl():
		return s.handleTask(ctx, raw, tokens, contractVersion)
	default:
		return s.reject(tokens, msg.IsControl(), newRejection(head.TaskID, head.RunID, "unsupported_kind",
			"Unsupported payload kind or MessageType combination."))
	}
}

func (s *Server) reject(tokens []Part, control bool, rej Rejection) *Message {
	reply, _ := replyStructured(rej, control, tokens, "Rejected: "+rej.Code+".")
	return reply
}

func (s *Server) handleTask(ctx context.Context, raw json.RawMessage, tokens []Part, ver string) *Message {
	// ver is "1.0" or "2.0": it selects the schema_version of every payload this call produces.
	wantCap := capabilityVersion
	dims := operationDims
	if ver == contractV2 {
		wantCap, dims = capabilityVersionV2, v2OperationDims
	}
	rej := func(code, message, taskID, runID string) *Message {
		r := newRejection(taskID, runID, code, message)
		r.SchemaVersion = ver
		return s.reject(tokens, false, r)
	}
	t, err := decodeTask(raw)
	if err != nil {
		var head struct {
			TaskID string `json:"task_id"`
			RunID  string `json:"run_id"`
		}
		_ = json.Unmarshal(raw, &head) // best effort: only used to label the rejection
		return rej("invalid_request", err.Error()+".", head.TaskID, head.RunID)
	}
	now := s.now()
	deadline, err := parseTime(t.Deadline)
	if err != nil {
		return rej("invalid_request", "deadline is invalid.", t.TaskID, t.RunID)
	}
	if !now.Before(deadline) {
		return rej("deadline_exceeded", "The task deadline had passed on receipt.", t.TaskID, t.RunID)
	}
	if deadline.Sub(now) > maxTaskDeadlineS*time.Second {
		return rej("invalid_request", fmt.Sprintf("deadline is more than %d s after receipt.", maxTaskDeadlineS), t.TaskID, t.RunID)
	}
	if t.CapabilityVersion != wantCap {
		return rej("unsupported_capability_version", "capability_version must be "+wantCap+".", t.TaskID, t.RunID)
	}
	for _, op := range t.Operations {
		if _, ok := dims[op]; !ok {
			msg := fmt.Sprintf("Operation %s is not in this specialist's capability.", op)
			if _, v2only := v2OperationDims[op]; v2only && ver != contractV2 {
				msg = fmt.Sprintf("Operation %s requires contract 2.0 (with the contract token).", op)
			}
			return rej("operation_not_supported", msg, t.TaskID, t.RunID)
		}
	}
	if t.Context.Language != "go" {
		return rej("context_mismatch", "Only language go is supported.", t.TaskID, t.RunID)
	}
	// Revision binding: a digest revision must name one of the inputs.
	var input *ArtifactRef
	for i := range t.Inputs {
		if t.Inputs[i].Digest == t.Context.RequestedRevision || (input == nil && !strings.HasPrefix(t.Context.RequestedRevision, "sha256:")) {
			input = &t.Inputs[i]
		}
	}
	if input == nil {
		return rej("context_mismatch", "requested_revision does not match any input artifact digest.", t.TaskID, t.RunID)
	}

	if ver == contractV2 {
		if len(t.Operations) != 1 {
			return rej("invalid_request", "A 2.0 task names exactly one operation.", t.TaskID, t.RunID)
		}
		if h := v2Handlers[t.Operations[0]]; h != nil {
			return h(s, ctx, t, input, deadline.Add(-responseReserve), tokens)
		}
	}
	res := &Result{Kind: "result", SchemaVersion: ver, TaskID: t.TaskID, RunID: t.RunID, Context: t.Context,
		Producer: Producer{ServiceID: serviceID, Implementation: "go", CapabilityVersion: wantCap,
			OperationsUsed: []string{}, DimensionsUsed: []string{}},
		Evidence: []EvidenceItem{}, Claims: []Claim{}, Artifacts: []ProducedArtifact{},
		MissingEvidence: []MissingEvidence{}, Warnings: []string{}, Errors: []DomainError{}}
	if ver == contractV2 {
		res.CaptureSetID = t.CaptureSetID // a 2.0 result echoes the task's capture set (V10)
	}

	allowedOps := map[string]bool{}
	for _, op := range t.Operations {
		allowedOps[op] = true
	}
	var supported []Requirement
	for _, req := range t.Requirements {
		if req.Dimension == operationDims[opGoModInventory] && allowedOps[opGoModInventory] {
			supported = append(supported, req)
			continue
		}
		reason := "unsupported_dimension"
		if req.Dimension == operationDims[opGoModInventory] {
			reason = "unsupported_operation"
		}
		res.MissingEvidence = append(res.MissingEvidence, MissingEvidence{RequirementID: req.RequirementID,
			Dimension: req.Dimension, Reason: reason,
			Detail: fmt.Sprintf("Dimension %s is outside this specialist's negotiated capability (inventory only).", req.Dimension)})
	}
	finish := func(status, summary string) *Message {
		res.Status = status
		res.CompletedAt = s.now().Format(timeLayout)
		reply, _ := replyStructured(res, false, tokens, summary)
		return reply
	}
	fail := func(code, message string) *Message {
		res.Errors = append(res.Errors, DomainError{Code: code, Message: message, Retryable: false})
		for _, req := range supported {
			res.MissingEvidence = append(res.MissingEvidence, MissingEvidence{RequirementID: req.RequirementID,
				Dimension: req.Dimension, Reason: "worker_failed", Detail: "No evidence: " + code + "."})
		}
		return finish("failed", "Failed: "+code+"; no evidence returned.")
	}
	if len(supported) == 0 {
		return finish("unsupported", "Unsupported: no requirement is within capability; nothing was run.")
	}
	if *t.Budget.MaxWorkerJobs < 1 {
		return fail("budget_exhausted", "The task budget allows no worker job.")
	}
	gomod, err := s.store.Read(input.Digest)
	if err != nil {
		if errors.Is(err, errIntegrity) {
			return fail("artifact_integrity_failure", "Input artifact bytes do not match their digest.")
		}
		return fail("artifact_not_found", "Input artifact is not in the store.")
	}
	out, parsed, code, err := s.worker.GoModInventory(ctx, gomod, deadline.Add(-responseReserve))
	if err != nil {
		return fail(code, err.Error()+".")
	}
	limit := *t.Budget.MaxProducedArtifactBytes
	if len(out) > limit || len(out) > maxProducedBytes {
		return fail("output_too_large", "Produced artifact exceeds the task budget.")
	}
	sum := sha256.Sum256(out)
	outDigest := "sha256:" + hex.EncodeToString(sum[:])
	stamp := s.now().Format(timeLayout)
	res.Artifacts = append(res.Artifacts, ProducedArtifact{Digest: outDigest, MediaType: "application/json", Bytes: len(out),
		ContentB64: base64.StdEncoding.EncodeToString(out), Producer: serviceID + "/" + opGoModInventory,
		SourceRef: input.Digest, CapturedAt: stamp, Role: "raw_tool_output"})
	res.Producer.OperationsUsed = []string{opGoModInventory}
	res.Producer.DimensionsUsed = []string{"inventory"}
	method := CollectionMethod{Tool: "go mod edit -json", ToolVersion: s.worker.goVersion,
		ArgvTemplate: []string{"go", "mod", "edit", "-json", "<private-temp-copy>/go.mod"}, OutputArtifact: outDigest}
	for i, req := range parsed.Require {
		evID := fmt.Sprintf("%s.ev%d", t.TaskID, i+1)
		direct := "a direct"
		if req.Indirect {
			direct = "an indirect"
		}
		res.Evidence = append(res.Evidence, EvidenceItem{EvidenceID: evID, Dimension: "inventory", Kind: "module_requirement",
			Subject:          Subject{Module: req.Path, Version: req.Version, Indirect: req.Indirect},
			ArtifactRef:      ArtifactRef{Digest: input.Digest, MediaType: input.MediaType},
			Locator:          fmt.Sprintf("go.mod#Require[%d]", i),
			Observation:      fmt.Sprintf("go.mod records %s requirement on %s %s.", direct, req.Path, req.Version),
			CollectionMethod: method,
			Scope:            "go.mod require directives only, as declared in the input artifact.",
			Limitations: []string{
				"Declared requirement only: does not establish that the module is downloaded, built, executed or vulnerable.",
				"Module graph not resolved (GOPROXY=off, no go.sum verification).",
			},
			ObservedAt: stamp})
		res.Claims = append(res.Claims, Claim{ClaimID: fmt.Sprintf("%s.cl%d", t.TaskID, i+1), Type: "module_requirement_recorded",
			Dimension:   "inventory",
			Proposition: fmt.Sprintf("The input go.mod records a requirement on %s %s.", req.Path, req.Version),
			EvidenceIDs: []string{evID}, Status: "supported",
			Explanation: "Supported by inventory evidence " + evID + " from go mod edit -json."})
	}
	if len(res.MissingEvidence) > 0 {
		return finish("partial", fmt.Sprintf("Partial: %d inventory items; %d requirement(s) unsupported and left unknown.",
			len(res.Evidence), len(res.MissingEvidence)))
	}
	return finish("complete", fmt.Sprintf("Complete: %d inventory items from go.mod.", len(res.Evidence)))
}
