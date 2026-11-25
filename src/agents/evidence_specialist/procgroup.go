package main

import (
	"os/exec"
	"syscall"
	"time"
)

// killGroupOnCancel makes a cancelled or timed-out command take its whole process group
// down, and bounds how long Wait lingers on pipes that grandchildren still hold open.
// Without it a shell wrapper killed at the deadline leaves its child holding stdout, and
// the job overruns the deadline (found by TestWorkerBlockedPastDeadlineReturnsBeforeDeadline).
func killGroupOnCancel(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = 500 * time.Millisecond
}
