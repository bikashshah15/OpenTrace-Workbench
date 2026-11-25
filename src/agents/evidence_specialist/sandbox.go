package main

// Sandboxed job execution for the major 2.0 operations (I2-REQ-07). Every subprocess runs as
//
//	unshare --net -- prlimit --cpu=.. --as=.. --fsize=.. --nofile=.. -- <command>
//
// in a private workspace with an exact environment allowlist and output caps. If a network
// namespace cannot be created nothing runs: there is no unsandboxed fallback. This is process
// isolation, not a container: RLIMIT_NPROC is not enforced for uid 0 and there is no cgroup.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

var errSandboxUnavailable = errors.New("sandbox_unavailable")

// Sandbox holds the resolved helper binaries and the netns flavour that works here.
type Sandbox struct {
	unshare, prlimit string
	netArgs          []string
}

// NewSandbox resolves unshare and prlimit from pathEnv and proves a network namespace can be made.
func NewSandbox(pathEnv string) (*Sandbox, error) {
	look := func(name string) (string, error) {
		for _, dir := range filepath.SplitList(pathEnv) {
			p := filepath.Join(dir, name)
			if fi, err := os.Stat(p); err == nil && !fi.IsDir() && fi.Mode()&0o111 != 0 {
				return p, nil
			}
		}
		return "", errSandboxUnavailable
	}
	us, err := look("unshare")
	if err != nil {
		return nil, err
	}
	pl, err := look("prlimit")
	if err != nil {
		return nil, err
	}
	for _, args := range [][]string{{"--net"}, {"--user", "--map-root-user", "--net"}} {
		probe := append(append([]string{}, args...), "--", "true")
		if exec.Command(us, probe...).Run() == nil {
			return &Sandbox{unshare: us, prlimit: pl, netArgs: args}, nil
		}
	}
	return nil, errSandboxUnavailable
}

// Limits for one command (contract section 5).
type Limits2 struct {
	Wall   time.Duration
	CPU    int    // seconds
	AS     uint64 // bytes
	FSize  uint64
	NoFile int
	OutCap int // per stream
}

const gib = uint64(1) << 30

var (
	limGitApply = Limits2{30 * time.Second, 30, 2 * gib, 16 << 20, 256, 64 << 10}
	limVerify   = Limits2{60 * time.Second, 60, 6 * gib, 64 << 20, 1024, 1 << 20}
	limBuild    = Limits2{120 * time.Second, 120, 6 * gib, 64 << 20, 1024, 1 << 20}
	limList     = Limits2{30 * time.Second, 30, 4 * gib, 16 << 20, 512, 1 << 20}
	limVuln     = Limits2{180 * time.Second, 180, 6 * gib, 64 << 20, 1024, 1 << 20}
)

type cmdResult struct {
	Stdout, Stderr []byte
	Exit           int
	Duration       time.Duration
	MaxRSSKB       int64
	TimedOut       bool
	Overflow       bool
	Err            error // could not start / unexpected
}

// sandboxRuns counts commands actually started (tests assert "nothing was executed").
var sandboxRuns int64

// Run executes argv inside the sandbox. jobDeadline bounds the wall time together with lim.Wall.
func (s *Sandbox) Run(parent context.Context, argv []string, dir string, env []string, lim Limits2, jobDeadline time.Time) cmdResult {
	wall := lim.Wall
	if remaining := time.Until(jobDeadline); remaining < wall {
		wall = remaining
	}
	if wall <= 0 {
		return cmdResult{Exit: -1, TimedOut: true}
	}
	ctx, cancel := context.WithTimeout(parent, wall)
	defer cancel()
	atomic.AddInt64(&sandboxRuns, 1)
	full := append([]string{}, s.netArgs...)
	full = append(full, "--", s.prlimit, fmt.Sprintf("--cpu=%d", lim.CPU), fmt.Sprintf("--as=%d", lim.AS),
		fmt.Sprintf("--fsize=%d", lim.FSize), fmt.Sprintf("--nofile=%d", lim.NoFile), "--")
	full = append(full, argv...)
	cmd := exec.CommandContext(ctx, s.unshare, full...)
	cmd.Dir, cmd.Env = dir, env
	killGroupOnCancel(cmd)
	out, errb := &cappedBuffer{max: lim.OutCap}, &cappedBuffer{max: lim.OutCap}
	cmd.Stdout, cmd.Stderr = out, errb
	started := time.Now()
	runErr := cmd.Run()
	res := cmdResult{Stdout: out.buf.Bytes(), Stderr: errb.buf.Bytes(), Duration: time.Since(started),
		Overflow: out.overflow || errb.overflow}
	if cmd.ProcessState != nil {
		res.Exit = cmd.ProcessState.ExitCode()
		if ru, ok := cmd.ProcessState.SysUsage().(*syscall.Rusage); ok {
			res.MaxRSSKB = int64(ru.Maxrss)
		}
	} else {
		res.Exit = -1
	}
	switch {
	case ctx.Err() == context.DeadlineExceeded:
		res.TimedOut = true
	case runErr != nil && cmd.ProcessState == nil:
		res.Err = runErr
	}
	return res
}

// jobEnv is the exact allowlist (contract section 2.3 plus section 3.7): nothing is inherited.
func jobEnv(w *Worker, dir string) []string {
	path := strings.Join(uniqueDirs(filepath.Dir(w.goBin), filepath.Dir(w.gitBin), w.toolDir), ":")
	return []string{
		"PATH=" + path, "HOME=" + dir, "TMPDIR=" + dir,
		"GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off", "GOFLAGS=-mod=readonly", "GOENV=off",
		"GOMODCACHE=" + w.modcache, "GOCACHE=" + filepath.Join(dir, "gocache"), "GOPATH=" + filepath.Join(dir, "gopath"),
		"CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64", "GOTELEMETRY=off",
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1",
	}
}

func uniqueDirs(dirs ...string) []string {
	seen, out := map[string]bool{}, []string{}
	for _, d := range dirs {
		if d != "" && d != "." && !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	return out
}

// pathNormalizer rewrites absolute local paths before any output is stored (contract section 3.6).
type pathRule struct{ from, to string }

type pathNormalizer struct {
	rules  []pathRule
	counts map[string]int
}

func newNormalizer(rules ...pathRule) *pathNormalizer {
	n := &pathNormalizer{counts: map[string]int{}}
	for _, r := range rules {
		if r.from != "" && r.from != "/" {
			n.rules = append(n.rules, r)
		}
	}
	// longest prefix first so a nested directory is not half-rewritten
	for i := range n.rules {
		for j := i + 1; j < len(n.rules); j++ {
			if len(n.rules[j].from) > len(n.rules[i].from) {
				n.rules[i], n.rules[j] = n.rules[j], n.rules[i]
			}
		}
	}
	return n
}

func (n *pathNormalizer) apply(b []byte) []byte {
	for _, r := range n.rules {
		c := bytes.Count(b, []byte(r.from))
		if c > 0 {
			n.counts[r.to] += c
			b = bytes.ReplaceAll(b, []byte(r.from), []byte(r.to))
		}
	}
	return b
}

func (n *pathNormalizer) summary() map[string]any {
	out := map[string]any{}
	for _, r := range n.rules {
		out[r.to] = n.counts[r.to]
	}
	return out
}
