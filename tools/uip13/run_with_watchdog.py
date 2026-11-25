"""UIP-13 validation (test harness): run one browser driver under a portable hard deadline. Usage: run_with_watchdog.py <cap_seconds> <outdir> -- <command...>

Starts the command in its own session, exports OT_DEADLINE_MS and OT_PIDS_FILE, and on expiry terminates ONLY the process group it started plus the PIDs the drivers
appended to the pidfile (fixture service, Chrome). It never touches any other process, container or resource. Exit code: the command's, or 124 on expiry.
"""
import os
import signal
import subprocess
import sys
import time


def main():
    cap, out = int(sys.argv[1]), sys.argv[2]
    cmd = sys.argv[sys.argv.index("--") + 1:]
    os.makedirs(out, exist_ok=True)
    pidfile = os.path.join(out, "pids.txt")
    open(pidfile, "w").close()
    env = dict(os.environ, OT_DEADLINE_MS=str(int((time.time() + cap) * 1000)), OT_PIDS_FILE=pidfile)
    proc = subprocess.Popen(cmd, env=env, start_new_session=True)
    try:
        rc = proc.wait(timeout=cap + 20)
    except subprocess.TimeoutExpired:
        rc = 124
        for pid in [proc.pid] + [int(x) for x in open(pidfile).read().split() if x.isdigit()]:
            try:
                os.killpg(os.getpgid(pid), signal.SIGTERM) if pid == proc.pid else os.kill(pid, signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                pass
        time.sleep(3)
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
    leftovers = []
    for pid in [int(x) for x in open(pidfile).read().split() if x.isdigit()]:
        try:
            os.kill(pid, 0)
            leftovers.append(pid)
        except (ProcessLookupError, PermissionError):
            pass
    print(f"watchdog: rc={rc} cap={cap}s leftover_owned_pids={leftovers}")
    sys.exit(rc)


if __name__ == "__main__":
    main()
