// Command evidence-specialist is OpenTrace Evidence Specialist B (I1): an
// independent Go NLIP service bound to loopback only (PD-03, development mode).
package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// checkLoopback refuses any address whose host is not a literal loopback IP.
func checkLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid --addr: %v", err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("refusing non-loopback --addr: I1 is loopback-only development mode")
	}
	return nil
}

func writePortFile(path string, port int) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(strconv.Itoa(port)+"\n"), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// newHTTPServer applies the I2-REQ-01 limits: WriteTimeout must not cut a task off before its
// deadline, so it is MAX_TASK_DEADLINE_S + 30 s rather than the I1 default deadline.
func newHTTPServer(h http.Handler) *http.Server {
	return &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: (maxTaskDeadlineS + 30) * time.Second}
}

func run() error {
	addr := flag.String("addr", "127.0.0.1:0", "loopback listen address")
	store := flag.String("store", "", "read-only content-addressed artifact store directory")
	portFile := flag.String("port-file", "", "file to receive the bound port")
	toolDir := flag.String("tool-dir", "", "directory holding the pinned govulncheck binary (I2)")
	modCache := flag.String("modcache", "", "primed module cache for offline builds (I2)")
	flag.Parse()
	if err := checkLoopback(*addr); err != nil {
		return err
	}
	if *store == "" {
		return errors.New("--store is required")
	}
	root, err := filepath.Abs(*store)
	if err != nil {
		return err
	}
	worker, err := NewWorker()
	if err != nil {
		return err
	}
	worker.configureV2(*toolDir, *modCache)
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		return err
	}
	if err := checkLoopback(ln.Addr().String()); err != nil {
		ln.Close()
		return err
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if *portFile != "" {
		if err := writePortFile(*portFile, port); err != nil {
			ln.Close()
			return err
		}
	}
	log.Printf("evidence-specialist-b listening on loopback port %d (%s)", port, worker.goVersion)
	return newHTTPServer(NewServer(root, worker)).Serve(ln)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "evidence-specialist:", err)
		os.Exit(2)
	}
}
