#!/usr/bin/env python3
"""`docker exec` / `run` / `attach` / `cp` on ANOTHER machine need an approval.

Locally these four stay free: test runs and throwaway containers are everyday
work, and an approval per test run is exactly the fatigue that eats a guard —
people click it through without looking.

Beyond a remote call stands the production system. On 2026-08-18 the
maintainer's own setup deleted rows from a production database this way
without any approval: a remote call, inside it an exec into the service
container, inside that a Python process. Each station on its own counted as
harmless. The maintainer's copy has refused that shape since; this file pins
it for the public one.

Remote means:
  1. `ssh` / `mosh` at the command position — also behind a wrapper
     (`timeout 5 ssh …`, `nice ssh …`),
  2. a container call that brings its own target (`-H`, `--host`, `--context`),
  3. the quoted text behind `ssh` / `eval` / `sh -c` — it ends at the SAME
     quote it started with, so `ssh h "echo 'x'; docker exec db …"` is read
     as one remote command and not as `echo `.

Pinned in both directions: the free half shows that local runs, read-only
remote calls and prose mentioning the words stay free.
"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
HOOK = Path(os.environ.get("GUARD_HOOK") or (REPO / "hooks" / "command-guard.py"))
RULES = REPO / "security-rules.example.json"


def _bash(command):
    with tempfile.TemporaryDirectory() as tmp:
        env = dict(os.environ)
        env["CLAUDE_SECURITY_RULES"] = str(RULES)
        env["CLAUDE_SUDO_OVERRIDES_DIR"] = tmp
        env["CLAUDE_AUDIT_DIR"] = tmp
        env["CLAUDE_HOOK_DEV_FLAG"] = tmp + "/_none"
        env["CLAUDE_GUARD_CONFIG"] = tmp + "/_no_config.json"
        payload = {"tool_name": "Bash", "tool_input": {"command": command},
                   "session_id": "remote-container", "cwd": tmp,
                   "hook_event_name": "PreToolUse"}
        r = subprocess.run([sys.executable, str(HOOK)], input=json.dumps(payload),
                           capture_output=True, text=True, env=env, timeout=60, cwd=tmp)
        return r.returncode


REMOTE = [
    'ssh prod "docker exec db ls"',
    "ssh prod docker exec db ls",
    "ssh prod 'docker run --rm alpine id'",
    "ssh prod docker attach web",
    "ssh prod docker cp evil.sh web:/app/",
    "mosh prod -- docker exec db ls",
    "timeout 5 ssh prod docker exec db ls",
    "nice ssh prod docker exec db rm -rf /data",
    "docker -H ssh://prod exec db ls",
    "docker --host tcp://10.0.0.5:2375 run --rm alpine id",
    "docker --context prod exec db ls",
    "sudo docker -H ssh://prod exec db ls",
    # the quoted command ends at the SAME quote it started with
    "ssh prod \"echo 'p'; docker exec db rm -rf /data\"",
    "ssh prod 'echo \"p\"; docker exec db psql'",
    "ssh prod \"psql -c \\\"SELECT 1\\\"; docker exec db psql\"",
    "ssh prod \"echo 'p'; docker exec db psql",          # quote never closed
    "bash -c \"echo 'p'; ssh prod docker exec db psql\"",
    "timeout 120 ssh prod \"docker exec db psql -c \\\"DELETE FROM t\\\"\"",
]

FREE = [
    "docker exec db ls",
    "docker run --rm alpine id",
    "docker cp a.txt web:/tmp/",
    "docker attach web",
    'ssh prod "docker ps"',
    "ssh prod docker logs --tail 50 web",
    "ssh prod 'docker inspect db'",
    "docker -H ssh://prod ps",
    "docker --context prod logs web",
    'echo "run ssh prod docker exec db ls to check"',
    'grep -rn "docker exec" docs/',
    "ssh prod uptime",
]


def check_remote_exec_run_attach_cp_blocked():
    return [c for c in REMOTE if _bash(c) != 2]


def check_local_and_read_only_remote_free():
    return [c for c in FREE if _bash(c) != 0]


CHECKS = [(name, fn) for name, fn in sorted(globals().items())
          if name.startswith("check_") and callable(fn)]


def test_remote_container_exec():
    failed = {name: bad for name, fn in CHECKS if (bad := fn())}
    assert not failed, f"{len(failed)} of {len(CHECKS)} failed: {failed}"


if __name__ == "__main__":
    total = 0
    for name, fn in CHECKS:
        bad = fn()
        total += bool(bad)
        print(f"  {'FAIL' if bad else 'ok  '}  {name}" + (f"  {bad}" if bad else ""))
    print(f"\n{len(CHECKS) - total} of {len(CHECKS)} passed")
    sys.exit(1 if total else 0)
