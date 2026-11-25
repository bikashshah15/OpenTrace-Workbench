package main

import (
	"strings"
	"testing"
)

// Real-capture finding (I2): govulncheck_source emits code_presence (package-level) and inventory
// (module-level) evidence besides call_path, so the 2.0 capability must negotiate all of them.
func TestV2CapabilityAdvertisesTheDimensionsGovulncheckEmits(t *testing.T) {
	srv, _ := newTestServer(t, fixtureGoMod)
	_, msg := post(t, srv, v2Envelope(map[string]any{"kind": "capability_request", "schema_version": "2.0", "request_id": "cap-4",
		"requester": map[string]any{"service_id": "a", "implementation": "python"}, "contract_versions": []any{"2.0"}}, "cap-4", true, true))
	var got []string
	for _, d := range content(t, msg)["dimensions"].([]any) {
		got = append(got, d.(string))
	}
	if want := "call_path,change_validation,code_presence,inventory"; strings.Join(got, ",") != want {
		t.Fatalf("dimensions %v", got)
	}
}
