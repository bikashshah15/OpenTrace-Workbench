package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ---- I2-REQ-01 (I1-IR-05) -------------------------------------------------------------

// T6: a worker blocked past the task deadline yields a failed/worker_timeout result before
// the deadline, so it reaches A before A's deadline+grace limit.
func TestWorkerBlockedPastDeadlineReturnsBeforeDeadline(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "go")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nsleep 30\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	store := t.TempDir()
	if err := os.MkdirAll(filepath.Join(store, "sha256"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(store, "sha256", fixtureDigest[7:]), []byte(fixtureGoMod), 0o444); err != nil {
		t.Fatal(err)
	}
	w := &Worker{goBin: fake, pathEnv: os.Getenv("PATH"), goVersion: "go1.24.7", maxOutput: maxProducedBytes, timeout: workerTimeout}
	srv := httptest.NewServer(NewServer(store, w))
	t.Cleanup(srv.Close)
	deadline := time.Now().UTC().Add(2 * time.Second)
	started := time.Now()
	status, msg := post(t, srv, envelope(taskPayload(func(p map[string]any) {
		p["deadline"] = deadline.Format(timeLayout)
	}), "run-1"))
	elapsed := time.Since(started)
	if status != 200 {
		t.Fatalf("status %d", status)
	}
	if elapsed >= 2*time.Second {
		t.Fatalf("response took %v, want before the 2 s deadline", elapsed)
	}
	res := msg["Content"].(map[string]any)
	if res["status"] != "failed" {
		t.Fatalf("status %v, want failed", res["status"])
	}
	errs := res["errors"].([]any)
	if len(errs) != 1 || errs[0].(map[string]any)["code"] != "worker_timeout" {
		t.Fatalf("errors %v, want worker_timeout", errs)
	}
}

// T7: server limits follow the maximum task deadline, and the deadline horizon is bounded.
func TestServerLimitsAndDeadlineHorizon(t *testing.T) {
	srv := newHTTPServer(http.NotFoundHandler())
	if srv.WriteTimeout < 930*time.Second {
		t.Fatalf("WriteTimeout %v is below 930 s", srv.WriteTimeout)
	}
	s, _ := newTestServer(t, fixtureGoMod)
	for _, tc := range []struct {
		secs int
		code string
	}{{901, "invalid_request"}, {899, ""}} {
		status, msg := post(t, s, envelope(taskPayload(func(p map[string]any) {
			p["deadline"] = time.Now().UTC().Add(time.Duration(tc.secs) * time.Second).Format(timeLayout)
		}), "run-1"))
		if status != 200 {
			t.Fatalf("status %d", status)
		}
		c := msg["Content"].(map[string]any)
		if tc.code != "" && (c["kind"] != "rejection" || c["code"] != tc.code) {
			t.Fatalf("deadline +%d s: got %v", tc.secs, c)
		}
		if tc.code == "" && c["kind"] != "result" {
			t.Fatalf("deadline +%d s: want a result, got %v", tc.secs, c)
		}
	}
}
