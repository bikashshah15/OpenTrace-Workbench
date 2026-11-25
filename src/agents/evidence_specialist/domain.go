package main

// Domain payloads for opentrace.evidence v1, validated by B itself. B shares no
// code with Investigator A or the core; the shared contract is contracts/evidence/v1.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	serviceID          = "evidence-specialist-b"
	contractV2         = "2.0"
	capabilityVersion  = "1.0"
	contractVersion    = "1.0"
	supportedMajor     = 1
	opGoModInventory   = "go_mod_inventory"
	timeLayout         = "2006-01-02T15:04:05.000Z"
	maxProducedBytes   = 256 * 1024 // PD-08
	maxProducedBytesV2 = 1 << 20    // I2 contract section 5
	workerTimeout      = 10 * time.Second
	defaultDeadlineS   = 30
	// I2-REQ-01: ordering invariant command_limit <= deadline-reserve < deadline+grace (A's grace is 2 s).
	maxTaskDeadlineS = 900
	responseReserve  = 1 * time.Second
)

var (
	identifierRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$`)
	digestRE     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	timestampRE  = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?Z$`)
	allDims      = map[string]bool{"inventory": true, "code_presence": true, "call_path": true, "crypto_discovery": true, "configuration": true, "runtime_observation": true, "change_validation": true}
	// Operation -> dimension it can establish.
	operationDims = map[string]string{opGoModInventory: "inventory"}
)

type Limits struct {
	ModelCalls               int `json:"model_calls"`
	NonLoopbackNetwork       int `json:"non_loopback_network"`
	MaxWorkerJobsPerTask     int `json:"max_worker_jobs_per_task"`
	WorkerTimeoutS           int `json:"worker_timeout_s"`
	DefaultTaskDeadlineS     int `json:"default_task_deadline_s"`
	MaxProducedArtifactBytes int `json:"max_produced_artifact_bytes"`
	// OperationLimits is a major 2.0 field; omitted from every 1.0 message.
	OperationLimits map[string]any `json:"operation_limits,omitempty"`
}

type CapabilityResponse struct {
	Kind              string   `json:"kind"`
	SchemaVersion     string   `json:"schema_version"`
	RequestID         string   `json:"request_id"`
	ServiceID         string   `json:"service_id"`
	Implementation    string   `json:"implementation"`
	CapabilityVersion string   `json:"capability_version"`
	ContractVersions  []string `json:"contract_versions"`
	Operations        []string `json:"operations"`
	Dimensions        []string `json:"dimensions"`
	Languages         []string `json:"languages"`
	Limits            Limits   `json:"limits"`
}

func capabilityFor(requestID string) CapabilityResponse {
	return CapabilityResponse{
		Kind: "capability_response", SchemaVersion: contractVersion, RequestID: requestID,
		ServiceID: serviceID, Implementation: "go", CapabilityVersion: capabilityVersion,
		ContractVersions: []string{contractVersion, contractV2, contractV3}, Operations: []string{opGoModInventory},
		Dimensions: []string{"inventory"}, Languages: []string{"go"},
		Limits: Limits{ModelCalls: 0, NonLoopbackNetwork: 0, MaxWorkerJobsPerTask: 1, WorkerTimeoutS: 10,
			DefaultTaskDeadlineS: defaultDeadlineS, MaxProducedArtifactBytes: maxProducedBytes},
	}
}

type Context struct {
	RepoID            string  `json:"repo_id"`
	RequestedRevision string  `json:"requested_revision"`
	ObservedRevision  *string `json:"observed_revision,omitempty"`
	BaselineID        string  `json:"baseline_id"`
	CandidateID       *string `json:"candidate_id"`
	Language          string  `json:"language"`
	BuildScope        string  `json:"build_scope"`
}

type ArtifactRef struct {
	Digest    string `json:"digest"`
	MediaType string `json:"media_type"`
	Role      string `json:"role,omitempty"`
}

type Requirement struct {
	RequirementID string `json:"requirement_id"`
	Dimension     string `json:"dimension"`
	Description   string `json:"description,omitempty"`
}

type Budget struct {
	MaxWorkerJobs            *int `json:"max_worker_jobs"`
	MaxProducedArtifactBytes *int `json:"max_produced_artifact_bytes"`
}

type TaskRequest struct {
	Kind              string          `json:"kind"`
	SchemaVersion     string          `json:"schema_version"`
	TaskID            string          `json:"task_id"`
	RunID             string          `json:"run_id"`
	CapabilityVersion string          `json:"capability_version"`
	IssuedAt          string          `json:"issued_at"`
	Deadline          string          `json:"deadline"`
	Context           Context         `json:"-"`
	RawContext        json.RawMessage `json:"context"`
	Requirements      []Requirement   `json:"requirements"`
	Operations        []string        `json:"operations"`
	Inputs            []ArtifactRef   `json:"inputs"`
	Budget            *Budget         `json:"budget"`
	CaptureSetID      string          `json:"capture_set_id"`
}

type Subject struct {
	Module   string `json:"module"`
	Version  string `json:"version"`
	Indirect bool   `json:"indirect"`
}

type CollectionMethod struct {
	Tool           string   `json:"tool"`
	ToolVersion    string   `json:"tool_version"`
	ArgvTemplate   []string `json:"argv_template"`
	OutputArtifact string   `json:"output_artifact"`
}

type EvidenceItem struct {
	EvidenceID       string           `json:"evidence_id"`
	Dimension        string           `json:"dimension"`
	Kind             string           `json:"kind"`
	Subject          Subject          `json:"subject"`
	ArtifactRef      ArtifactRef      `json:"artifact_ref"`
	Locator          string           `json:"locator"`
	Observation      string           `json:"observation"`
	CollectionMethod CollectionMethod `json:"collection_method"`
	Scope            string           `json:"scope"`
	Limitations      []string         `json:"limitations"`
	ObservedAt       string           `json:"observed_at"`
	// Details is a major 2.0 field, omitted from 1.0 evidence.
	Details any `json:"details,omitempty"`
}

type Claim struct {
	ClaimID     string   `json:"claim_id"`
	Type        string   `json:"type"`
	Dimension   string   `json:"dimension"`
	Proposition string   `json:"proposition"`
	EvidenceIDs []string `json:"evidence_ids"`
	Status      string   `json:"status"`
	Explanation string   `json:"explanation"`
	// Major 2.0 optional claim fields (omitted from 1.0 claims).
	VulnID   string `json:"vuln_id,omitempty"`
	QueryKey string `json:"query_key,omitempty"`
	CheckID  string `json:"check_id,omitempty"`
	Variant  string `json:"variant,omitempty"`
}

type ProducedArtifact struct {
	Digest     string `json:"digest"`
	MediaType  string `json:"media_type"`
	Bytes      int    `json:"bytes"`
	ContentB64 string `json:"content_b64"`
	Producer   string `json:"producer"`
	SourceRef  string `json:"source_ref"`
	CapturedAt string `json:"captured_at"`
	Role       string `json:"role"`
}

type MissingEvidence struct {
	RequirementID string `json:"requirement_id"`
	Dimension     string `json:"dimension"`
	Reason        string `json:"reason"`
	Detail        string `json:"detail,omitempty"`
	QueryKey      string `json:"query_key,omitempty"` // major 2.0
}

type DomainError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

type Producer struct {
	ServiceID         string   `json:"service_id"`
	Implementation    string   `json:"implementation"`
	CapabilityVersion string   `json:"capability_version"`
	OperationsUsed    []string `json:"operations_used"`
	DimensionsUsed    []string `json:"dimensions_used"`
}

type Result struct {
	Kind            string             `json:"kind"`
	SchemaVersion   string             `json:"schema_version"`
	TaskID          string             `json:"task_id"`
	RunID           string             `json:"run_id"`
	Producer        Producer           `json:"producer"`
	Context         Context            `json:"context"`
	Status          string             `json:"status"`
	Evidence        []EvidenceItem     `json:"evidence"`
	Claims          []Claim            `json:"claims"`
	Artifacts       []ProducedArtifact `json:"artifacts"`
	MissingEvidence []MissingEvidence  `json:"missing_evidence"`
	Warnings        []string           `json:"warnings"`
	Errors          []DomainError      `json:"errors"`
	CompletedAt     string             `json:"completed_at"`
	// Major 2.0 optional fields (omitted from 1.0 results).
	CaptureSetID string        `json:"capture_set_id,omitempty"`
	ChangeResult *ChangeResult `json:"change_result,omitempty"`
}

type Rejection struct {
	Kind          string  `json:"kind"`
	SchemaVersion string  `json:"schema_version"`
	TaskID        *string `json:"task_id"`
	RunID         *string `json:"run_id"`
	Code          string  `json:"code"`
	Message       string  `json:"message"`
	Retryable     bool    `json:"retryable"`
}

func newRejection(taskID, runID, code, message string) Rejection {
	r := Rejection{Kind: "rejection", SchemaVersion: contractVersion, Code: code, Message: message}
	if identifierRE.MatchString(taskID) {
		r.TaskID = &taskID
	}
	if identifierRE.MatchString(runID) {
		r.RunID = &runID
	}
	return r
}

// schemaMajor returns the major of "M.m"; ok is false when the field is malformed.
func schemaMajor(v string) (int, bool) {
	parts := strings.SplitN(v, ".", 2)
	if len(parts) != 2 {
		return 0, false
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil || major < 0 {
		return 0, false
	}
	if _, err := strconv.Atoi(parts[1]); err != nil {
		return 0, false
	}
	return major, true
}

func parseTime(s string) (time.Time, error) {
	if !timestampRE.MatchString(s) {
		return time.Time{}, fmt.Errorf("invalid timestamp %q", s)
	}
	return time.Parse(time.RFC3339Nano, s)
}

// decodeTask performs B's own structural validation of a task_request.
func decodeTask(raw json.RawMessage) (*TaskRequest, error) {
	var t TaskRequest
	if err := json.Unmarshal(raw, &t); err != nil {
		return nil, errors.New("task_request does not match the expected types")
	}
	switch {
	case t.Kind != "task_request":
		return nil, errors.New("kind must be task_request")
	case !identifierRE.MatchString(t.TaskID) || !identifierRE.MatchString(t.RunID):
		return nil, errors.New("task_id and run_id must be identifiers")
	case !timestampRE.MatchString(t.IssuedAt) || !timestampRE.MatchString(t.Deadline):
		return nil, errors.New("issued_at and deadline must be UTC timestamps")
	case len(t.Requirements) == 0 || len(t.Requirements) > 16:
		return nil, errors.New("requirements must have 1..16 entries")
	case len(t.Operations) == 0:
		return nil, errors.New("operations must not be empty")
	case len(t.Inputs) == 0 || len(t.Inputs) > 8:
		return nil, errors.New("inputs must have 1..8 entries")
	case t.Budget == nil || t.Budget.MaxWorkerJobs == nil || t.Budget.MaxProducedArtifactBytes == nil:
		return nil, errors.New("budget is required")
	case len(t.RawContext) == 0:
		return nil, errors.New("context is required")
	}
	// Context is a closed object (README): reject unknown fields.
	dec := json.NewDecoder(bytes.NewReader(t.RawContext))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&t.Context); err != nil {
		return nil, errors.New("context is malformed or has unknown fields")
	}
	var probe map[string]json.RawMessage
	_ = json.Unmarshal(t.RawContext, &probe)
	for _, f := range []string{"repo_id", "requested_revision", "baseline_id", "candidate_id", "language", "build_scope"} {
		if _, ok := probe[f]; !ok {
			return nil, fmt.Errorf("context.%s is required", f)
		}
	}
	if !identifierRE.MatchString(t.Context.RepoID) || t.Context.RequestedRevision == "" || t.Context.Language == "" {
		return nil, errors.New("context identity fields are invalid")
	}
	for _, r := range t.Requirements {
		if !identifierRE.MatchString(r.RequirementID) || !allDims[r.Dimension] {
			return nil, errors.New("requirement has an invalid id or dimension")
		}
	}
	for _, in := range t.Inputs {
		if !digestRE.MatchString(in.Digest) || in.MediaType == "" {
			return nil, errors.New("inputs must be artifact refs by sha256 digest")
		}
	}
	return &t, nil
}
