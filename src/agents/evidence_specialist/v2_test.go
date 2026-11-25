package main

import (
	"encoding/json"
	"testing"
	"time"
)

func contractToken(version string) map[string]any {
	return map[string]any{"Format": "token", "Subformat": contractTokenSubformat, "Content": version}
}

func v2Envelope(payload any, token string, control bool, withToken bool) map[string]any {
	env := envelope(payload, token)
	subs := env["Submessages"].([]any)
	if withToken {
		subs = append(subs, contractToken("2.0"))
	}
	env["Submessages"] = subs
	if control {
		env["MessageType"] = "control"
	}
	return env
}

func v2Task(mutate func(map[string]any)) map[string]any {
	return taskPayload(func(p map[string]any) {
		p["schema_version"] = "2.0"
		p["capability_version"] = "2.0"
		p["budget"] = map[string]any{"max_worker_jobs": 1, "max_produced_artifact_bytes": 1048576}
		if mutate != nil {
			mutate(p)
		}
	})
}

func subformats(msg map[string]any) []string {
	var out []string
	for _, s := range msg["Submessages"].([]any) {
		out = append(out, s.(map[string]any)["Subformat"].(string))
	}
	return out
}

func hasSub(msg map[string]any, subformat string) bool {
	for _, s := range subformats(msg) {
		if s == subformat {
			return true
		}
	}
	return false
}

// U10c / I1 R2: a bare 2.0 task (no token) is rejected with a 1.0 rejection.
func TestV2GatingBareMajor2IsA1Rejection(t *testing.T) {
	srv, _ := newTestServer(t, fixtureGoMod)
	status, msg := post(t, srv, envelope(v2Task(nil), "run-1"))
	c := content(t, msg)
	if status != 200 || c["kind"] != "rejection" || c["code"] != "unsupported_schema_version" || c["schema_version"] != "1.0" {
		t.Fatalf("bare 2.0 task: status %d, %v", status, c)
	}
	if hasSub(msg, contractTokenSubformat) {
		t.Fatal("a 1.0 rejection must not carry the contract token")
	}
}

func TestV2GatingTokenDisagreeingOrUnknownIsRejected(t *testing.T) {
	srv, _ := newTestServer(t, fixtureGoMod)
	// token 2.0 with a 1.0 payload
	_, msg := post(t, srv, v2Envelope(taskPayload(nil), "run-1", false, true))
	if c := content(t, msg); c["code"] != "unsupported_schema_version" || c["schema_version"] != "1.0" {
		t.Fatalf("token 2.0 + payload 1.0: %v", c)
	}
	// token naming an unknown contract with a 2.0 payload
	env := envelope(v2Task(nil), "run-1")
	env["Submessages"] = append(env["Submessages"].([]any), contractToken("3.0"))
	_, msg = post(t, srv, env)
	if c := content(t, msg); c["code"] != "unsupported_schema_version" || c["schema_version"] != "1.0" {
		t.Fatalf("token 3.0: %v", c)
	}
	// a major 3 payload is always a 1.0 rejection
	_, msg = post(t, srv, envelope(taskPayload(func(p map[string]any) { p["schema_version"] = "3.0" }), "run-1"))
	if c := content(t, msg); c["code"] != "unsupported_schema_version" || c["schema_version"] != "1.0" {
		t.Fatalf("major 3: %v", c)
	}
}

// Exchange matrix, legacy side: the 1.0-profile reply lists 2.0 and 3.0 and offers nothing a 1.0 peer cannot parse.
func TestV2LegacyProfileReply(t *testing.T) {
	srv, _ := newTestServer(t, fixtureGoMod)
	_, msg := post(t, srv, v2Envelope(map[string]any{"kind": "capability_request", "schema_version": "1.0", "request_id": "cap-1",
		"requester": map[string]any{"service_id": "a", "implementation": "python"}, "contract_versions": []any{"1.0"}}, "cap-1", true, false))
	c := content(t, msg)
	if c["schema_version"] != "1.0" || c["capability_version"] != "1.0" {
		t.Fatalf("1.0-profile reply: %v", c)
	}
	cv := c["contract_versions"].([]any)
	if len(cv) != 3 || cv[0] != "1.0" || cv[1] != "2.0" || cv[2] != "3.0" {
		t.Fatalf("contract_versions %v", cv)
	}
	if ops := c["operations"].([]any); len(ops) != 1 || ops[0] != "go_mod_inventory" {
		t.Fatalf("operations %v", ops)
	}
	if dims := c["dimensions"].([]any); len(dims) != 1 || dims[0] != "inventory" {
		t.Fatalf("dimensions %v", dims)
	}
	if _, has := c["limits"].(map[string]any)["operation_limits"]; has {
		t.Fatal("operation_limits is a 2.0 field and must not appear in a 1.0 message")
	}
	if hasSub(msg, contractTokenSubformat) {
		t.Fatal("1.0 reply carries the contract token")
	}
}

func TestV2CapabilityExchangeEchoesToken(t *testing.T) {
	srv, _ := newTestServer(t, fixtureGoMod)
	_, msg := post(t, srv, v2Envelope(map[string]any{"kind": "capability_request", "schema_version": "2.0", "request_id": "cap-2",
		"requester": map[string]any{"service_id": "a", "implementation": "python"}, "contract_versions": []any{"2.0"}}, "cap-2", true, true))
	c := content(t, msg)
	if msg["MessageType"] != "control" || c["schema_version"] != "2.0" || c["capability_version"] != "2.0" {
		t.Fatalf("2.0 capability reply: %v", msg)
	}
	if !hasSub(msg, contractTokenSubformat) {
		t.Fatal("contract token not echoed")
	}
	if _, has := c["limits"].(map[string]any)["operation_limits"]; !has {
		t.Fatal("2.0 capability lacks operation_limits")
	}
}

func TestV2InventoryAtMajor2(t *testing.T) {
	srv, _ := newTestServer(t, fixtureGoMod)
	status, msg := post(t, srv, v2Envelope(v2Task(nil), "run-1", false, true))
	c := content(t, msg)
	if status != 200 || c["kind"] != "result" || c["schema_version"] != "2.0" || c["status"] != "complete" {
		t.Fatalf("2.0 inventory: %d %v", status, c)
	}
	if len(c["evidence"].([]any)) != 3 {
		t.Fatalf("want 3 evidence items, got %d", len(c["evidence"].([]any)))
	}
	if !hasSub(msg, contractTokenSubformat) || !hasSub(msg, correlationSubformat) {
		t.Fatal("tokens not echoed")
	}
	// capability_version must be 2.0 for a 2.0 task
	_, msg = post(t, srv, v2Envelope(v2Task(func(p map[string]any) { p["capability_version"] = "1.0" }), "run-1", false, true))
	if c := content(t, msg); c["code"] != "unsupported_capability_version" || c["schema_version"] != "2.0" {
		t.Fatalf("capability_version mismatch: %v", c)
	}
}

func TestV2OperationNotInV1(t *testing.T) {
	srv, _ := newTestServer(t, fixtureGoMod)
	for _, op := range []string{"osv_advisory_match", "govulncheck_source", "change_validate"} {
		_, msg := post(t, srv, envelope(taskPayload(func(p map[string]any) { p["operations"] = []any{op} }), "run-1"))
		c := content(t, msg)
		if c["code"] != "operation_not_supported" || c["schema_version"] != "1.0" {
			t.Fatalf("1.0 task naming %s: %v", op, c)
		}
	}
}

func TestV2ExactlyOneOperationAndHorizon(t *testing.T) {
	srv, _ := newTestServer(t, fixtureGoMod)
	_, msg := post(t, srv, v2Envelope(v2Task(func(p map[string]any) {
		p["operations"] = []any{"go_mod_inventory", "osv_advisory_match"}
	}), "run-1", false, true))
	if c := content(t, msg); c["code"] != "invalid_request" && c["code"] != "operation_not_supported" {
		t.Fatalf("two operations: %v", c)
	}
	_, msg = post(t, srv, v2Envelope(v2Task(func(p map[string]any) {
		p["deadline"] = time.Now().UTC().Add(901 * time.Second).Format(timeLayout)
	}), "run-1", false, true))
	if c := content(t, msg); c["code"] != "invalid_request" || c["schema_version"] != "2.0" {
		t.Fatalf("horizon: %v", c)
	}
}

func TestV2JSONShapeOfLegacyResultUnchanged(t *testing.T) {
	// 1.0 results must not contain any 2.0-only key (omitempty additions).
	srv, _ := newTestServer(t, fixtureGoMod)
	_, msg := post(t, srv, envelope(taskPayload(nil), "run-1"))
	raw, _ := json.Marshal(content(t, msg))
	for _, key := range []string{"capture_set_id", "change_result", "details", "operation_limits", "vuln_id", "query_key"} {
		if json.Valid(raw) && containsKey(raw, key) {
			t.Fatalf("1.0 result contains 2.0-only key %q", key)
		}
	}
}

func containsKey(raw []byte, key string) bool {
	var v any
	_ = json.Unmarshal(raw, &v)
	var walk func(any) bool
	walk = func(x any) bool {
		switch t := x.(type) {
		case map[string]any:
			for k, vv := range t {
				if k == key || walk(vv) {
					return true
				}
			}
		case []any:
			for _, vv := range t {
				if walk(vv) {
					return true
				}
			}
		}
		return false
	}
	return walk(v)
}

func nowPlus(seconds int) string {
	return time.Now().UTC().Add(time.Duration(seconds) * time.Second).Format(timeLayout)
}
