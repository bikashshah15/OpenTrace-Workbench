package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const fixtureGoMod = "module example.com/opentrace/fixture/i1\n\ngo 1.22\n\nrequire (\n\tgithub.com/google/uuid v1.6.0\n\tgolang.org/x/text v0.14.0\n)\n\nrequire golang.org/x/sys v0.15.0 // indirect\n"
const fixtureDigest = "sha256:38eb8de4d5c72ffbe83edeaedf13770a696b51dec0e7c74a44edeaa7e290b92b"

func newTestServer(t *testing.T, content string) (*httptest.Server, string) {
	t.Helper()
	store := t.TempDir()
	if err := os.MkdirAll(filepath.Join(store, "sha256"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(store, "sha256", fixtureDigest[7:]), []byte(content), 0o444); err != nil {
		t.Fatal(err)
	}
	w, err := NewWorker()
	if err != nil {
		t.Fatalf("worker: %v", err)
	}
	srv := httptest.NewServer(NewServer(store, w))
	t.Cleanup(srv.Close)
	return srv, store
}

func taskPayload(mutate func(map[string]any)) map[string]any {
	now := time.Now().UTC()
	p := map[string]any{
		"kind": "task_request", "schema_version": "1.0", "task_id": "t1", "run_id": "run-1",
		"capability_version": "1.0", "issued_at": now.Format(timeLayout),
		"deadline": now.Add(30 * time.Second).Format(timeLayout),
		"context": map[string]any{"repo_id": "opentrace-fixture/i1-gomod-basic", "requested_revision": fixtureDigest,
			"baseline_id": "baseline", "candidate_id": nil, "language": "go", "build_scope": "go.mod require directives only"},
		"requirements": []any{map[string]any{"requirement_id": "req-1", "dimension": "inventory"}},
		"operations":   []any{"go_mod_inventory"},
		"inputs":       []any{map[string]any{"digest": fixtureDigest, "media_type": "text/plain"}},
		"budget":       map[string]any{"max_worker_jobs": 1, "max_produced_artifact_bytes": 262144},
	}
	if mutate != nil {
		mutate(p)
	}
	return p
}

func envelope(payload any, token string) map[string]any {
	return map[string]any{"Format": "structured", "Subformat": "json", "Content": payload,
		"Submessages": []any{map[string]any{"Format": "token", "Subformat": correlationSubformat, "Content": token}}}
}

func post(t *testing.T, srv *httptest.Server, body any) (int, map[string]any) {
	t.Helper()
	var raw []byte
	if b, ok := body.([]byte); ok {
		raw = b
	} else {
		raw, _ = json.Marshal(body)
	}
	resp, err := http.Post(srv.URL+"/nlip", "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("response is not JSON: %v", err)
	}
	return resp.StatusCode, out
}

func content(t *testing.T, msg map[string]any) map[string]any {
	t.Helper()
	c, ok := msg["Content"].(map[string]any)
	if !ok {
		t.Fatalf("no structured content in %v", msg)
	}
	return c
}

func TestLoopbackRefusal(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:0", "10.1.2.3:80", "[::]:0", "localhost:0", "example.com:80", "nonsense"} {
		if checkLoopback(addr) == nil {
			t.Errorf("%s accepted", addr)
		}
	}
	for _, addr := range []string{"127.0.0.1:0", "127.0.0.2:8080", "[::1]:0"} {
		if err := checkLoopback(addr); err != nil {
			t.Errorf("%s refused: %v", addr, err)
		}
	}
}

func TestCompleteResult(t *testing.T) {
	srv, _ := newTestServer(t, fixtureGoMod)
	status, msg := post(t, srv, envelope(taskPayload(nil), "run-1"))
	res := content(t, msg)
	if status != 200 || res["status"] != "complete" {
		t.Fatalf("status %d result %v", status, res["status"])
	}
	ev := res["evidence"].([]any)
	if len(ev) != 3 || len(res["claims"].([]any)) != 3 {
		t.Fatalf("want 3 evidence/claims, got %d", len(ev))
	}
	third := ev[2].(map[string]any)
	subj := third["subject"].(map[string]any)
	if subj["module"] != "golang.org/x/sys" || subj["indirect"] != true || third["locator"] != "go.mod#Require[2]" {
		t.Fatalf("unexpected third item %v", third)
	}
	art := res["artifacts"].([]any)[0].(map[string]any)
	if art["media_type"] != "application/json" || art["source_ref"] != fixtureDigest {
		t.Fatalf("bad produced artifact %v", art)
	}
}

func TestPartialVersusComplete(t *testing.T) {
	srv, _ := newTestServer(t, fixtureGoMod)
	_, msg := post(t, srv, envelope(taskPayload(func(p map[string]any) {
		p["requirements"] = []any{map[string]any{"requirement_id": "req-1", "dimension": "inventory"},
			map[string]any{"requirement_id": "req-2", "dimension": "call_path"}}
	}), "run-1"))
	res := content(t, msg)
	missing := res["missing_evidence"].([]any)
	if res["status"] != "partial" || len(missing) != 1 || missing[0].(map[string]any)["reason"] != "unsupported_dimension" {
		t.Fatalf("want partial with call_path missing, got %v %v", res["status"], missing)
	}
	for _, c := range res["claims"].([]any) {
		if c.(map[string]any)["dimension"] != "inventory" {
			t.Fatalf("non-inventory claim %v", c)
		}
	}
	_, msg = post(t, srv, envelope(taskPayload(func(p map[string]any) {
		p["requirements"] = []any{map[string]any{"requirement_id": "req-2", "dimension": "call_path"}}
	}), "run-1"))
	if res := content(t, msg); res["status"] != "unsupported" || len(res["evidence"].([]any)) != 0 {
		t.Fatalf("want unsupported with no evidence, got %v", res["status"])
	}
}

func TestSchemaMajorRejection(t *testing.T) {
	srv, _ := newTestServer(t, fixtureGoMod)
	status, msg := post(t, srv, envelope(taskPayload(func(p map[string]any) { p["schema_version"] = "2.0" }), "run-1"))
	rej := content(t, msg)
	if status != 200 || rej["kind"] != "rejection" || rej["code"] != "unsupported_schema_version" {
		t.Fatalf("got %d %v", status, rej)
	}
	_, msg = post(t, srv, envelope(taskPayload(func(p map[string]any) { p["schema_version"] = "1.9" }), "run-1"))
	if content(t, msg)["kind"] != "result" {
		t.Fatal("minor version 1.9 must be accepted")
	}
}

func TestDigestVerification(t *testing.T) {
	srv, _ := newTestServer(t, strings.Replace(fixtureGoMod, "v1.6.0", "v1.6.1", 1))
	_, msg := post(t, srv, envelope(taskPayload(nil), "run-1"))
	res := content(t, msg)
	errs := res["errors"].([]any)
	if res["status"] != "failed" || len(errs) != 1 || errs[0].(map[string]any)["code"] != "artifact_integrity_failure" ||
		len(res["claims"].([]any)) != 0 {
		t.Fatalf("want failed integrity, got %v", res)
	}
	store := Store{root: t.TempDir()}
	if _, err := store.Read("sha256:" + strings.Repeat("0", 64)); err != errNotFound {
		t.Fatalf("missing artifact: %v", err)
	}
	if _, err := store.Read("../../etc/passwd"); err != errNotFound {
		t.Fatal("non-digest reference must not resolve")
	}
}

func TestStoreReadRehashes(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "sha256"), 0o755)
	data := []byte("hello")
	sum := sha256.Sum256(data)
	d := "sha256:" + hex.EncodeToString(sum[:])
	os.WriteFile(filepath.Join(dir, "sha256", d[7:]), data, 0o444)
	got, err := Store{root: dir}.Read(d)
	if err != nil || string(got) != "hello" {
		t.Fatalf("read: %v", err)
	}
}

func TestDeadlineRejection(t *testing.T) {
	srv, _ := newTestServer(t, fixtureGoMod)
	_, msg := post(t, srv, envelope(taskPayload(func(p map[string]any) {
		p["deadline"] = time.Now().UTC().Add(-time.Second).Format(timeLayout)
	}), "run-1"))
	if rej := content(t, msg); rej["code"] != "deadline_exceeded" {
		t.Fatalf("got %v", rej)
	}
}

func TestOperationAndContextChecks(t *testing.T) {
	srv, _ := newTestServer(t, fixtureGoMod)
	_, msg := post(t, srv, envelope(taskPayload(func(p map[string]any) { p["operations"] = []any{"shell"} }), "run-1"))
	if c := content(t, msg); c["code"] != "operation_not_supported" {
		t.Fatalf("got %v", c)
	}
	_, msg = post(t, srv, envelope(taskPayload(func(p map[string]any) {
		p["context"].(map[string]any)["requested_revision"] = "sha256:" + strings.Repeat("1", 64)
	}), "run-1"))
	if c := content(t, msg); c["code"] != "context_mismatch" {
		t.Fatalf("got %v", c)
	}
	_, msg = post(t, srv, envelope(taskPayload(func(p map[string]any) {
		p["context"].(map[string]any)["extra"] = "x"
	}), "run-1"))
	if c := content(t, msg); c["code"] != "invalid_request" {
		t.Fatalf("closed context: got %v", c)
	}
}

func TestTokenEcho(t *testing.T) {
	srv, _ := newTestServer(t, fixtureGoMod)
	for _, payload := range []any{taskPayload(nil), taskPayload(func(p map[string]any) { p["schema_version"] = "3.0" })} {
		_, msg := post(t, srv, envelope(payload, "run-xyz"))
		subs := msg["Submessages"].([]any)
		tok := subs[0].(map[string]any)
		if tok["Format"] != "token" || tok["Subformat"] != correlationSubformat || tok["Content"] != "run-xyz" {
			t.Fatalf("token not echoed unchanged: %v", subs)
		}
		texts := 0
		for _, s := range subs {
			if s.(map[string]any)["Format"] == "text" && s.(map[string]any)["Subformat"] == "english" {
				texts++
			}
		}
		if texts != 1 {
			t.Fatalf("want exactly one text/english summary, got %d", texts)
		}
	}
	// capability exchange also echoes the token and is a control message
	_, msg := post(t, srv, map[string]any{"messagetype": "CONTROL", "FORMAT": "Structured", "subformat": "json",
		"content": map[string]any{"kind": "capability_request", "schema_version": "1.0", "request_id": "cap-1",
			"requester": map[string]any{"service_id": "a", "implementation": "python"}, "contract_versions": []any{"1.0"}},
		"Submessages": []any{map[string]any{"format": "token", "subformat": correlationSubformat, "content": "cap-1"}}})
	if msg["MessageType"] != "control" || content(t, msg)["service_id"] != serviceID {
		t.Fatalf("bad capability reply %v", msg)
	}
	if msg["Submessages"].([]any)[0].(map[string]any)["Content"] != "cap-1" {
		t.Fatal("capability token not echoed")
	}
}

func TestBadRequestPath(t *testing.T) {
	srv, _ := newTestServer(t, fixtureGoMod)
	cases := [][]byte{[]byte("not json {"), []byte(`{"Subformat":"english","Content":"x"}`),
		[]byte(`{"Format":"video","Subformat":"x","Content":"x"}`), []byte(`{"Format":"text","Subformat":"english"}`),
		[]byte(`{"Format":"text","Subformat":"english","Content":"x","Submessages":[{"Format":"token"}]}`), []byte(`[]`)}
	for _, body := range cases {
		status, msg := post(t, srv, body)
		if status != 400 || msg["Format"] != "text" || msg["Subformat"] != "english" {
			t.Errorf("%s: got %d %v", body, status, msg)
		}
	}
}

func TestTextMessageReply(t *testing.T) {
	srv, _ := newTestServer(t, fixtureGoMod)
	status, msg := post(t, srv, map[string]any{"Format": "TEXT", "Subformat": "english", "Content": "hello?"})
	if status != 200 || msg["Format"] != "text" || !strings.Contains(msg["Content"].(string), "go_mod_inventory") {
		t.Fatalf("got %d %v", status, msg)
	}
}

func TestWorkerEnvironmentIsFixed(t *testing.T) {
	env := workerEnv("/usr/bin", "/tmp/x")
	want := []string{"PATH=/usr/bin", "HOME=/tmp/x", "GOTOOLCHAIN=local", "GOPROXY=off", "GOFLAGS=", "GOENV=off"}
	if strings.Join(env, "|") != strings.Join(want, "|") {
		t.Fatalf("env %v", env)
	}
}

func TestWorkerOutputCap(t *testing.T) {
	w, err := NewWorker()
	if err != nil {
		t.Fatal(err)
	}
	w.maxOutput = 16
	_, _, code, err := w.GoModInventory(context.Background(), []byte(fixtureGoMod), time.Now().Add(10*time.Second))
	if err == nil || code != "output_too_large" {
		t.Fatalf("want output_too_large, got %q %v", code, err)
	}
}

func TestMethodAndPath(t *testing.T) {
	srv, _ := newTestServer(t, fixtureGoMod)
	resp, err := http.Get(srv.URL + "/nlip")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET /nlip: %d", resp.StatusCode)
	}
	resp, err = http.Post(srv.URL+"/other", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("POST /other: %d", resp.StatusCode)
	}
}
