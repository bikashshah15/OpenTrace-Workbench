#!/usr/bin/env python3
"""Start OpenTrace with one command.

    python3 tools/start.py                       default `no-llm` profile: Workbench + isolated scanner worker (no key, no config file)
    python3 tools/start.py --profile with-llm    adds live Cisco AI-BOM and the Lab Assistant (needs opentrace.yml with one OpenAI key file)

Options: --check (validate and run the read-only preflight; start nothing), --replace (stop and remove this project's OpenTrace containers
first; volumes, ledgers and unrelated containers are kept), --project NAME, --port N.

This is a thin layer over the existing Compose services and tools/uip07c/aibom_preflight.py (it reuses that module's checks and its start order:
the Cisco AI services must verify before the Workbench starts). It never prints, logs or passes a secret VALUE: the key file's path travels in
the environment of the `docker compose` process, and Compose mounts the file as a Docker secret. Plain `docker compose` workflows are unchanged.
Standard library only.
"""
import argparse
import importlib.util
import os
import secrets
import shlex
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, ".."))
sys.path.insert(0, os.path.join(HERE, "uip07c"))
import aibom_preflight as PF  # noqa: E402  (reused, not copied)

PROFILES = ("no-llm", "with-llm")
LIVE_PROVIDER = "openai"
UNSUPPORTED_PROVIDERS = {"anthropic": "Anthropic Claude", "claude": "Anthropic Claude", "google": "Google Gemini", "gemini": "Google Gemini"}
MANAGED = ("workbench", "worker", "gateway", "aibom-worker", "assistant-provider")
AI_SIDE = ("gateway", "aibom-worker", "assistant-provider")
IMAGES_PREBUILT = ("opentrace-aibom-worker:uip07c", "opentrace-gateway:uip07c")
# The only OPENTRACE_* variables start.py lets through from the caller's shell. Every other OPENTRACE_* variable (the AI switches, key and
# token file paths, pricing, billing flag) is dropped, so an inherited setting can never switch LLM features on in `no-llm`, or change `with-llm`.
MAX_DISPATCH_ALLOWANCE = 10_000        # mirrors opentrace_core.app.assistant.accounting.MAX_DISPATCH_ALLOWANCE (a test keeps them equal)
PASS_THROUGH = ("OPENTRACE_PORT", "OPENTRACE_LIVE_POLICY", "OPENTRACE_LIVE_ADVISORIES", "OPENTRACE_AIBOM_CONTEXT", "OPENTRACE_GATEWAY_CONTEXT")
DROPPED_COMPOSE = ("COMPOSE_PROFILES", "COMPOSE_FILE", "COMPOSE_PROJECT_NAME", "COMPOSE_ENV_FILES", "COMPOSE_PATH_SEPARATOR")
SECRETS_DIR = os.path.join(".opentrace", "secrets")
TOKEN_NAME = "assistant-broker-token"
BUILD_DOC = "python3 tools/uip07c/build_aibom_images.py (see deploy/docker/README.md, 'Optional Cisco AI-BOM phase')"


class Stop(Exception):
    """A condition under which start.py stops. Carries the messages to print and the exit status."""

    def __init__(self, problems, code=1):
        super().__init__("; ".join(problems))
        self.problems, self.code = list(problems), code


# -- opentrace.yml ----------------------------------------------------------------------------------------------------------------------
def parse_config(text):
    """A deliberately tiny YAML subset: nested `key: value` mappings by two-space indentation, `#` comments, plain/quoted scalars. Anything else is refused,
    so the launcher needs no PyYAML on a fresh checkout and cannot misread a file it does not understand."""
    root, stack = {}, [(-1, {})]
    stack[0] = (-1, root)
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.split(" #", 1)[0] if not raw.lstrip().startswith("#") else ""
        if not line.strip():
            continue
        if "\t" in line[: len(line) - len(line.lstrip())]:
            raise Stop(["opentrace.yml line %d: tabs are not allowed for indentation" % number])
        indent = len(line) - len(line.lstrip(" "))
        key, sep, value = line.strip().partition(":")
        if not sep or not key or key.startswith("-") or " " in key:
            raise Stop(["opentrace.yml line %d: expected `key: value` (lists and other YAML are not supported)" % number])
        while stack and indent <= stack[-1][0]:
            stack.pop()
        if not stack:
            raise Stop(["opentrace.yml line %d: bad indentation" % number])
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        parent = stack[-1][1]
        if key in parent:
            raise Stop(["opentrace.yml line %d: duplicate key %r" % (number, key)])
        if value == "":
            parent[key] = {}
            stack.append((indent, parent[key]))
        else:
            parent[key] = value
    return root


def load_llm_section(path):
    if not os.path.isfile(path):
        raise Stop(["no %s found. Create it from the example, then rerun:" % os.path.basename(path),
                    "    cp opentrace.example.yml opentrace.yml      # then set llm.api_key_file to your OpenAI key file",
                    "(or run `python3 tools/start.py` for the no-llm profile, which needs no configuration)"])
    try:
        with open(path, encoding="utf-8") as handle:
            cfg = parse_config(handle.read())
    except (OSError, UnicodeError) as exc:
        raise Stop(["cannot read %s: %s" % (path, exc.__class__.__name__)])
    llm = cfg.get("llm")
    if not isinstance(llm, dict) or not llm:
        raise Stop(["%s has no active `llm:` section (the future-provider examples are comments); copy opentrace.example.yml" % os.path.basename(path)])
    unknown = sorted(set(llm) - {"provider", "api_key_file", "assistant_billing_verified", "gateway_pricing_file", "assistant_dispatch_allowance"})
    if unknown:
        raise Stop(["%s: unknown llm setting(s): %s" % (os.path.basename(path), ", ".join(unknown))])
    return llm


def inside(path, root):
    real, base = os.path.realpath(path), os.path.realpath(root)
    return os.path.commonpath([real, base]) == base


def validate_llm(llm, root=REPO):
    """Returns (settings, problems). Every problem is collected so the operator fixes them in one pass."""
    problems = []
    provider = str(llm.get("provider", "")).strip().lower()
    if provider in UNSUPPORTED_PROVIDERS:
        problems.append("llm.provider %r (%s) is not supported for live use in this version; OpenAI is the only live provider. Set `provider: openai`." % (llm.get("provider"), UNSUPPORTED_PROVIDERS[provider]))
    elif provider != LIVE_PROVIDER:
        problems.append("llm.provider %r is not recognised; the only live provider is `openai`." % llm.get("provider"))
    key = os.path.expanduser(str(llm.get("api_key_file", "")).strip())
    if not key:
        problems.append("llm.api_key_file is not set: give the absolute path of a file that contains your OpenAI API key.")
    elif not os.path.isabs(key):
        problems.append("llm.api_key_file must be an absolute path (got a relative one).")
    elif inside(key, root):
        problems.append("llm.api_key_file resolves to %s, inside the repository. Keep the key outside the checkout (for example ~/.config/opentrace/openai.key): "
                        "a key in the tree can be committed or sent in a Docker build context." % os.path.realpath(key))
    elif not os.path.isfile(key):
        problems.append("llm.api_key_file %s does not exist or is not a regular file." % key)
    elif not os.access(key, os.R_OK):
        problems.append("llm.api_key_file %s is not readable by you." % key)
    elif os.path.getsize(key) == 0:
        problems.append("llm.api_key_file %s is empty." % key)
    flag = str(llm.get("assistant_billing_verified", "false")).strip().lower()
    if flag not in ("true", "false"):
        problems.append("llm.assistant_billing_verified must be true or false.")
    allowance = str(llm.get("assistant_dispatch_allowance", "")).strip()
    if allowance and not (allowance.isascii() and allowance.isdigit() and 1 <= int(allowance) <= MAX_DISPATCH_ALLOWANCE):
        problems.append("llm.assistant_dispatch_allowance must be a whole number from 1 to %d (each question normally uses two dispatches)." % MAX_DISPATCH_ALLOWANCE)
    pricing = os.path.expanduser(str(llm.get("gateway_pricing_file", "")).strip())
    if pricing and not os.path.isabs(pricing):
        pricing = os.path.normpath(os.path.join(root, pricing))       # relative paths are relative to the checkout, never to the working directory
    return {"key": key, "billing_verified": flag == "true", "allowance": allowance, "pricing": pricing or os.path.join(REPO, "deploy", "docker", "gateway", "pricing.json")}, problems


def pricing_problem(path, now=None, root=REPO):
    """Reuses the gateway's own validation, so the launcher and the gateway can never disagree about a pricing record. A missing file gets the copy command as the fix;
    the launcher itself never creates or overwrites a record."""
    if not os.path.exists(path):
        shown = os.path.relpath(path, root) if inside(path, root) else path
        return ("gateway pricing record %s does not exist. Create your local copy from the committed template (the template is expired on purpose; `cp -n` never overwrites):\n"
                "      mkdir -p %s && cp -n deploy/docker/gateway/pricing.json %s\n"
                "    then verify the official pricing and update verified_on / valid_until / sources in YOUR copy (deploy/docker/gateway/README.md)."
                % (shown, shlex.quote(os.path.dirname(shown) or "."), shlex.quote(shown)))
    spec = importlib.util.spec_from_file_location("opentrace_gateway_pricing", os.path.join(REPO, "src", "workers", "gateway", "gateway.py"))
    gateway = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gateway)
    record, reason = gateway.load_pricing(path, time.time() if now is None else now)
    if reason is None:
        return None
    fix = ("The gateway refuses every dispatch without a current owner-issued pricing record (valid for at most 14 days). Re-verify the official pricing, write a fresh record "
           "in your local copy (see deploy/docker/gateway/README.md) and point llm.gateway_pricing_file at it.")
    what = {"pricing_expired": "has expired", "pricing_unreadable": "is missing or unreadable", "pricing_mismatch": "does not match the model and limits this program enforces"}.get(reason, "is malformed (%s)" % reason)
    return "gateway pricing record %s %s. %s" % (path, what, fix)


# -- environment ------------------------------------------------------------------------------------------------------------------------
def build_env(profile, settings, token_path, base):
    """The environment for every `docker compose` call. Starts from the caller's environment minus every OpenTrace/Compose switch, then adds only what the profile needs."""
    env = {k: v for k, v in base.items() if not (k.startswith("OPENTRACE_") and k not in PASS_THROUGH) and k not in DROPPED_COMPOSE}
    if profile == "with-llm":
        env.update({"OPENTRACE_LIVE_AIBOM": "cisco",
                    "OPENTRACE_PROVIDER_KEY_FILE": settings["key"],                  # same file: the Cisco gateway's provider_key secret ...
                    "OPENTRACE_ASSISTANT_OPENAI_KEY_FILE": settings["key"],          # ... and the Assistant provider's secret (paths only, never contents)
                    "OPENTRACE_ASSISTANT_BROKER_TOKEN_FILE": token_path,
                    "OPENTRACE_GATEWAY_PRICING": settings["pricing"],
                    "OPENTRACE_ASSISTANT_TOKEN_COUNT_COST_VERIFIED": "1" if settings["billing_verified"] else "0"})
        if settings.get("allowance"):
            env["OPENTRACE_ASSISTANT_DISPATCH_ALLOWANCE"] = settings["allowance"]
    return env


def make_runner(env, inner=None):
    """Runner for aibom_preflight and this module. Every `docker compose` call gets `--env-file <empty>`, so a repository .env cannot reintroduce AI settings."""
    def run(argv, timeout=60):
        argv = list(argv)
        if argv[:2] == ["docker", "compose"]:
            argv[2:2] = ["--env-file", os.devnull]
        if inner is not None:
            return inner(argv, timeout)
        try:
            done = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, env=env)
            return PF.Result(done.returncode, done.stdout, done.stderr)
        except subprocess.TimeoutExpired:
            return PF.Result(124, "", "timed out after %ss" % timeout)
        except OSError as exc:
            return PF.Result(127, "", str(exc))
    return run


def ensure_token(root):
    """The internal Assistant broker token: random, generated once, reused, mode 0600, under the ignored .opentrace/ directory (also in .dockerignore)."""
    directory = os.path.join(root, SECRETS_DIR)
    os.makedirs(directory, mode=0o700, exist_ok=True)
    path = os.path.join(directory, TOKEN_NAME)
    if os.path.isfile(path) and os.path.getsize(path) > 0:
        return path
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(secrets.token_urlsafe(32))
    os.chmod(path, 0o600)
    return path


# -- Docker -----------------------------------------------------------------------------------------------------------------------------
def tail(done):
    return (done.stderr or done.stdout or "").strip().splitlines()[-1:] or ["no output"]


def compose(runner, args, *rest, profiles=(), timeout=600):
    argv = ["docker", "compose", "-f", args.compose_file, "-p", args.project]
    for p in profiles:
        argv += ["--profile", p]
    return runner(argv + list(rest), timeout)


def require_docker(runner):
    done = runner(["docker", "version", "--format", "{{.Server.Version}}"], 30)
    if done.returncode != 0:
        raise Stop(["Docker is not available: %s" % tail(done)[0], "Start Docker Desktop (or the Docker Engine) and rerun."])
    done = runner(["docker", "compose", "version"], 30)
    if done.returncode != 0:
        raise Stop(["Docker Compose v2 is not available (`docker compose version` failed). Install Docker Desktop or the compose plugin."])


def missing_images(runner):
    return [i for i in IMAGES_PREBUILT if runner(["docker", "image", "inspect", i], 30).returncode != 0]


def engine_problem(runner):
    try:
        PF.check_engine(runner, False)
        return None
    except PF.Refusal as exc:
        text = str(exc)
        if "not verified" in text:
            return ("Docker platform not supported for live AI-BOM: %s. Cisco isolation is only admitted on the platform an independent test verified "
                    "(Docker Desktop 4.98.0 (245422), Engine 29.9.2, linux/arm64, kernel 7.0.14-linuxkit). Use `python3 tools/start.py` (no-llm) on this machine." % text)
        return "Docker Engine check failed: %s" % text


def inspect_stack(runner, project):
    rows = []
    for c in PF.inspect_project_containers(runner, project):
        service = PF._service(c)
        if service in MANAGED:
            env = (c.get("Config") or {}).get("Env") or []
            rows.append({"id": c["Id"], "service": service, "name": (c.get("Name") or "").lstrip("/"), "running": bool((c.get("State") or {}).get("Running")),
                         "ai": "OPENTRACE_LIVE_AIBOM=cisco" in env})
    return rows


def already_running(profile, rows):
    live = {r["service"] for r in rows if r["running"]}
    if profile == "no-llm":
        return live == {"workbench", "worker"} and not any(r["ai"] for r in rows) and len(rows) == 2
    return live == set(MANAGED) and len(rows) == len(MANAGED) and any(r["ai"] for r in rows if r["service"] == "workbench")


def needs_replace(profile, rows):
    """Compose can restart a stopped or healthy stack of the SAME profile in place. Switching needs the Workbench recreated (and, for with-llm, the Cisco start order,
    which refuses while any Workbench or AI container exists)."""
    if profile == "with-llm":
        return any(r["service"] in ("workbench",) + AI_SIDE for r in rows)
    return any(r["service"] in AI_SIDE or (r["service"] == "workbench" and r["ai"]) for r in rows)


def replace_steps(args, rows):
    names = " ".join(r["name"] for r in rows if r["service"] != "worker")
    return ["    docker stop %s" % names, "    docker rm %s            # no -v: volumes are kept" % names]


def explain_stack(args, profile, rows, log):
    log("An OpenTrace stack already exists in Compose project %r:" % args.project)
    for r in rows:
        log("    %-34s %-15s %s" % (r["name"], r["service"], "running" if r["running"] else "stopped"))
    log("Switching to the %s profile needs the Workbench (and any AI services) recreated, because the Cisco isolation check must pass before a Workbench exists." % profile)
    log("Exact steps (`python3 tools/start.py --profile %s --replace` does exactly these, nothing more):" % profile)
    for line in replace_steps(args, rows):
        log(line)
    log("Impact: the Workbench keeps sessions in memory, so any scan, session or Assistant chat in progress is LOST and open browser tabs must be reloaded.")
    log("Kept: every volume (spool volumes, gateway-ledger spend ledger, assistant-ledger), the AI network, the scanner worker container, other projects and unrelated containers.")


def replace_stack(runner, rows, log):
    ids = [r["id"] for r in rows if r["service"] != "worker"]
    if not ids:
        return
    for argv, what in ((["docker", "stop", "-t", "10"] + ids, "stop"), (["docker", "rm"] + ids, "remove")):
        done = runner(argv, 120)
        if done.returncode != 0:
            raise Stop(["could not %s the existing OpenTrace containers: %s" % (what, tail(done)[0]), "Nothing else was changed."])
    log("Stopped and removed %d OpenTrace container(s) of this project; volumes untouched." % len(ids))


REQUIRED = {"no-llm": ("workbench", "worker"), "with-llm": MANAGED}


def verify_running(runner, args, profile, log):
    """Never claim readiness unless Compose answered AND every service this profile needs is running. The query activates the profile's Compose profiles, since a
    profile-gated service is invisible to `compose ps` otherwise."""
    profiles = ("aibom", "assistant") if profile == "with-llm" else ()
    done = compose(runner, args, "ps", "--status", "running", "--format", "{{.Service}}", profiles=profiles, timeout=60)
    if done.returncode != 0:
        raise Stop(["Could not confirm that OpenTrace is running: `docker compose ps` failed: %s" % tail(done)[0],
                    "Check with: docker compose -p %s ps -a" % args.project])
    running = set(done.stdout.split())
    missing = [s for s in REQUIRED[profile] if s not in running]
    if missing:
        raise Stop(["OpenTrace (%s) is NOT ready: required service(s) not running: %s." % (profile, ", ".join(missing)),
                    "Running: %s" % (", ".join(sorted(running)) or "none"),
                    "See why with: docker compose -p %s%s logs %s" % (args.project, " --profile aibom --profile assistant" if profile == "with-llm" else "", " ".join(missing))])
    log("running: %s" % ", ".join(sorted(running)))


# -- profiles ---------------------------------------------------------------------------------------------------------------------------
PROBE = ("import sys\nfor p in sys.argv[1:]:\n    with open(p, 'rb') as h:\n        if not h.read(1):\n            sys.exit(3)\n")
PROBE_IMAGE = "opentrace-workbench:i6"


def build_images(runner, args, services_profiles):
    """Every image build, run BEFORE anything of the old stack is stopped."""
    for services, profiles in services_profiles:
        done = compose(runner, args, "build", *services, profiles=profiles)
        if done.returncode != 0:
            raise Stop(["building %s failed: %s" % (", ".join(services), tail(done)[0]), "Nothing was stopped or changed."])


def probe_secret_access(runner, files):
    """Proves, with a throw-away container run as the SAME non-root uid/gid the services use (10001) and with the same read-only bind mounts, that each secret file is
    readable by it. Nothing is printed from the files; the container has no network, a read-only root and no capabilities."""
    argv = ["docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--user", "10001:10001", "--entrypoint", "python"]
    targets = []
    for i, path in enumerate(files):
        argv += ["--mount", "type=bind,src=%s,dst=/probe/%d,readonly" % (path, i)]
        targets.append("/probe/%d" % i)
    done = runner(argv + [PROBE_IMAGE, "-I", "-c", PROBE] + targets, 120)
    if done.returncode != 0:
        raise Stop(["The key or broker-token file is not readable by the services' non-root user (uid/gid 10001), or Docker cannot share it: %s" % tail(done)[0],
                    "Docker Desktop on macOS maps ownership, so a 0600 file normally works there and the path must be in a shared folder (Settings > Resources > File sharing).",
                    "On Linux give uid 10001 ownership and keep it private: sudo chown 10001:10001 <file>; chmod 600 <file> (do this for each of: %s)." % ", ".join(files),
                    "Nothing was stopped or changed."])


def dry_preflight(runner, args, ignore, log):
    """The read-only Cisco checks (engine/platform, resolved Compose model, network and subnet) with the containers about to be replaced ignored. The full preflight and
    postflight still run again, unchanged, inside the real start (PF.up)."""
    ns = argparse.Namespace(project=args.project, compose_file=args.compose_file, require_fresh=False, ai_only=False, unverified_for_topo2=False, ignore_containers=set(ignore))
    try:
        PF.preflight(runner, ns, log)
    except PF.Refusal as exc:
        raise Stop(["REFUSED by the Cisco preflight: %s" % exc, "Nothing was stopped or changed."])


def start_no_llm(runner, args, log):
    done = compose(runner, args, "up", "-d", "--no-build", "--wait", "--wait-timeout", "300", "workbench", "worker")
    if done.returncode != 0:
        raise Stop(["docker compose up failed: %s" % tail(done)[0], "Run `docker compose -p %s logs workbench worker` to see why." % args.project])


def start_with_llm(runner, args, log):
    done = compose(runner, args, "up", "-d", "--no-build", "--wait", "--wait-timeout", "120", "assistant-provider", profiles=("assistant",))
    if done.returncode != 0:
        raise Stop(["the Assistant provider did not become healthy: %s" % tail(done)[0], "Run `docker compose -p %s --profile assistant logs assistant-provider`." % args.project])
    pf = argparse.Namespace(project=args.project, compose_file=args.compose_file, require_fresh=False, ai_only=False, unverified_for_topo2=False,
                            manifest=os.path.join(args.root, ".aibom-context", "topology-%s-manifest.json" % args.project))
    try:
        PF.up(runner, pf, log)             # the FULL Cisco preflight -> AI services -> postflight -> only then the Workbench
    except PF.Refusal as exc:
        raise Stop(["REFUSED by the Cisco isolation check: %s" % exc, "The Workbench was not started."])


def run(args, environ, inner=None, log=print):
    profile, root = args.profile, args.root
    if not args.compose_file_given:
        args.compose_file = os.path.join(root, "compose.yaml")
    settings = None
    config_path = os.path.join(root, "opentrace.yml")
    token_path = os.path.join(root, SECRETS_DIR, TOKEN_NAME)
    if profile == "with-llm":
        settings, problems = validate_llm(load_llm_section(config_path), root)
        p = pricing_problem(settings["pricing"], root=root)
        if p:
            problems.append(p)
        if not settings["billing_verified"]:
            problems.append("Assistant billing is not verified, so the Assistant would stay disabled. Verify how OpenAI bills the /v1/responses/input_tokens endpoint, "
                            "then set `assistant_billing_verified: true` under llm: in opentrace.yml (deploy/docker/gateway/README.md, LAB-ASSISTANT-01 notes).")
        env = build_env(profile, settings, token_path, environ)
        runner = make_runner(env, inner)
        require_docker(runner)
        missing = missing_images(runner)
        if missing:
            problems.append("Cisco AI-BOM image(s) not built: %s. They are built offline from a prepared context: %s." % (", ".join(missing), BUILD_DOC))
        p = engine_problem(runner)
        if p:
            problems.append(p)
        if problems:
            raise Stop(["with-llm cannot start:"] + ["  - " + x for x in problems])
        if os.stat(settings["key"]).st_mode & 0o077:
            log("warning: %s is readable by other users on this machine; consider `chmod 600` (the services read it through a Docker secret)." % settings["key"])
    else:
        env = build_env(profile, None, None, environ)
        runner = make_runner(env, inner)
        require_docker(runner)
        if os.path.isfile(config_path):
            log("note: opentrace.yml is ignored by the no-llm profile; no AI feature is enabled.")
    rows = inspect_stack(runner, args.project)
    replacing = bool(rows) and (args.replace or needs_replace(profile, rows))
    removing = [r for r in rows if r["service"] != "worker"] if replacing else []
    if rows and already_running(profile, rows) and not args.replace:
        log("OpenTrace (%s) is already running: %s" % (profile, url(env, args)))
        log("Use --replace to restart it.")
        return 0
    if rows and needs_replace(profile, rows) and not args.replace:
        explain_stack(args, profile, rows, log)
        raise Stop(["Nothing was changed. Rerun with --replace to apply these steps."], code=2)
    if args.check:
        # Strictly read-only: no token or other file is written, nothing is built, no container (not even a probe) is created.
        if profile == "with-llm":
            dry_preflight(runner, args, [r["id"] for r in removing], log)
            log("--check: configuration and the read-only Cisco preflight passed%s. Builds, the secret-access probe and the broker token happen at start; nothing was started or changed."
                % (" (with the existing stack ignored, as --replace would)" if removing else ""))
        else:
            log("--check: the no-llm profile needs nothing else; nothing was started.")
        return 0
    # -- real start: everything that can fail runs before the old stack is touched -------------------------------------------------------------
    if profile == "with-llm":
        ensure_token(root)
        build_images(runner, args, ((("workbench", "worker"), ()), (("assistant-provider",), ("assistant",))))
        probe_secret_access(runner, [settings["key"], token_path])
        dry_preflight(runner, args, [r["id"] for r in removing], log)
    else:
        build_images(runner, args, ((("workbench", "worker"), ()),))
    if replacing:
        explain_stack(args, profile, rows, log)
        replace_stack(runner, rows, log)
    start_with_llm(runner, args, log) if profile == "with-llm" else start_no_llm(runner, args, log)
    verify_running(runner, args, profile, log)
    log("OpenTrace (%s) is ready: %s" % (profile, url(env, args)))
    if profile == "with-llm":
        log("Live Cisco AI-BOM and the Lab Assistant are enabled. Spend limits are enforced by the gateway and Assistant ledgers (volumes are kept across restarts).")
    log("Stop it with: docker compose -p %s stop    (volumes and ledgers are kept)" % args.project)
    return 0


def url(env, args):
    return "http://127.0.0.1:%s/" % (args.port or env.get("OPENTRACE_PORT") or "8765")


def make_parser():
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--profile", choices=PROFILES, default="no-llm")
    p.add_argument("--check", action="store_true", help="validate everything and run the read-only preflight; start nothing")
    p.add_argument("--replace", action="store_true", help="stop and remove this project's existing OpenTrace containers first (volumes are kept)")
    p.add_argument("--project", default=PF.DEFAULT_PROJECT, help="Compose project name (default: %(default)s)")
    p.add_argument("--port", help="host port (default 8765, or OPENTRACE_PORT)")
    p.add_argument("--root", default=REPO, help=argparse.SUPPRESS)
    p.add_argument("--compose-file", default=None, help=argparse.SUPPRESS)
    return p


def main(argv=None, environ=None, inner=None, out=None):
    out = out or sys.stdout
    log = lambda msg: print(msg, file=out)
    args = make_parser().parse_args(argv)
    args.compose_file_given = args.compose_file is not None
    environ = dict(os.environ if environ is None else environ)
    if args.port:
        environ["OPENTRACE_PORT"] = args.port
    try:
        return run(args, environ, inner, log)
    except Stop as stop:
        for line in stop.problems:
            log(line)
        return stop.code
    except PF.Refusal as exc:
        log("REFUSED: %s" % exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
