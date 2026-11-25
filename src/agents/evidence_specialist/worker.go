package main

// The single allowlisted worker job: `go mod edit -json <private temp copy>`.
// Fixed argv, fixed minimal environment, 10 s timeout, output capped at 256 KiB.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var goVersionRE = regexp.MustCompile(`go version (go[0-9][0-9A-Za-z.+-]*)`)

// Store gives read-only access to the content-addressed store by digest only.
type Store struct{ root string }

var (
	errNotFound  = errors.New("artifact_not_found")
	errIntegrity = errors.New("artifact_integrity_failure")
)

const maxInputBytes = 1 << 20

// Read resolves sha256:<hex> to <root>/sha256/<hex>, re-hashes and returns the bytes.
func (s Store) Read(digest string) ([]byte, error) { return s.ReadMax(digest, maxInputBytes) }

// ReadMax is Read with an explicit size cap; larger artifacts are an integrity failure, never truncated.
func (s Store) ReadMax(digest string, max int) ([]byte, error) {
	if !digestRE.MatchString(digest) {
		return nil, errNotFound
	}
	f, err := os.Open(filepath.Join(s.root, "sha256", digest[len("sha256:"):]))
	if err != nil {
		return nil, errNotFound
	}
	defer f.Close()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(&limitReader{f: f, n: max + 1}); err != nil || buf.Len() > max {
		return nil, errIntegrity
	}
	sum := sha256.Sum256(buf.Bytes())
	if "sha256:"+hex.EncodeToString(sum[:]) != digest {
		return nil, errIntegrity
	}
	return buf.Bytes(), nil
}

type limitReader struct {
	f interface{ Read([]byte) (int, error) }
	n int
}

func (l *limitReader) Read(p []byte) (int, error) {
	if l.n <= 0 {
		return 0, errors.New("limit")
	}
	if len(p) > l.n {
		p = p[:l.n]
	}
	n, err := l.f.Read(p)
	l.n -= n
	return n, err
}

// cappedBuffer fails the copy once more than max bytes arrive.
type cappedBuffer struct {
	buf      bytes.Buffer
	max      int
	overflow bool
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if c.buf.Len()+len(p) > c.max {
		c.overflow = true
		return 0, errors.New("output cap exceeded")
	}
	return c.buf.Write(p)
}

// Worker runs the allowlisted job with the resolved go binary.
type Worker struct {
	goBin     string
	pathEnv   string
	goVersion string
	maxOutput int
	timeout   time.Duration

	// Major 2.0 (I2) job configuration; zero values mean "not configured".
	gitBin   string
	toolDir  string // directory holding the pinned govulncheck binary
	modcache string // primed, read-only module cache (class A1 output)
	goroot   string
	sandbox  *Sandbox // nil when a network namespace cannot be created
}

// configureV2 supplies the tool directory and module cache (flags --tool-dir, --modcache).
func (w *Worker) configureV2(toolDir, modcache string) {
	w.toolDir, w.modcache = toolDir, modcache
}

func workerEnv(pathEnv, home string) []string {
	return []string{"PATH=" + pathEnv, "HOME=" + home, "GOTOOLCHAIN=local", "GOPROXY=off", "GOFLAGS=", "GOENV=off"}
}

// NewWorker resolves `go` from PATH and probes its version once (`go version`, same env).
func NewWorker() (*Worker, error) {
	bin, err := exec.LookPath("go")
	if err != nil {
		return nil, fmt.Errorf("go toolchain not found on PATH")
	}
	w := &Worker{goBin: bin, pathEnv: os.Getenv("PATH"), maxOutput: maxProducedBytes, timeout: workerTimeout}
	home, err := os.MkdirTemp("", "otb-probe-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(home)
	ctx, cancel := context.WithTimeout(context.Background(), w.timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, w.goBin, "version")
	cmd.Env = workerEnv(w.pathEnv, home)
	cmd.Dir = home
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("go version probe failed")
	}
	m := goVersionRE.FindSubmatch(out)
	if m == nil {
		return nil, fmt.Errorf("go version probe returned unexpected output")
	}
	w.goVersion = string(m[1])
	w.gitBin, _ = exec.LookPath("git")
	if out, err := exec.Command(w.goBin, "env", "GOROOT").Output(); err == nil {
		w.goroot = strings.TrimSpace(string(out))
	}
	w.sandbox, _ = NewSandbox(w.pathEnv)
	return w, nil
}

type goModJSON struct {
	Require []struct {
		Path     string
		Version  string
		Indirect bool
	}
}

// GoModInventory copies the verified bytes into a private temp dir and runs the fixed argv.
func (w *Worker) GoModInventory(parent context.Context, gomod []byte, deadline time.Time) ([]byte, *goModJSON, string, error) {
	dir, err := os.MkdirTemp("", "otb-job-")
	if err != nil {
		return nil, nil, "worker_failed", err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(path, gomod, 0o600); err != nil {
		return nil, nil, "worker_failed", err
	}
	ctx, cancel := context.WithTimeout(parent, w.timeout)
	defer cancel()
	ctx, cancelDeadline := context.WithDeadline(ctx, deadline)
	defer cancelDeadline()
	cmd := exec.CommandContext(ctx, w.goBin, "mod", "edit", "-json", path)
	killGroupOnCancel(cmd)
	cmd.Env = workerEnv(w.pathEnv, dir)
	cmd.Dir = dir
	stdout := &cappedBuffer{max: w.maxOutput}
	stderr := &cappedBuffer{max: 4096}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	runErr := cmd.Run()
	switch {
	case stdout.overflow:
		return nil, nil, "output_too_large", errors.New("worker output exceeded the cap")
	case ctx.Err() != nil:
		return nil, nil, "worker_timeout", errors.New("worker exceeded its timeout or the task deadline")
	case runErr != nil:
		return nil, nil, "worker_failed", errors.New("go mod edit -json exited with an error")
	}
	var parsed goModJSON
	if err := json.Unmarshal(stdout.buf.Bytes(), &parsed); err != nil {
		return nil, nil, "worker_failed", errors.New("worker output is not the expected JSON")
	}
	return stdout.buf.Bytes(), &parsed, "", nil
}
