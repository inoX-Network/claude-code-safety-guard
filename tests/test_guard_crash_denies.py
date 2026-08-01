# ============================================================================
# A crash of the guard must DENY, not allow.
#
# Only exit code 2 means "deny" — everything else lets the command run. Before
# this net existed, any unhandled error killed the guard with exit code 1 and
# the command went through, looking exactly like a normal allow.
#
# Every case is a dry run: the hook is started as its own process with input on
# stdin, and only the exit code and stderr are read. No command is executed.
#
# NOTE ON METHOD: each artificial fault is checked for EFFECTIVENESS (its marker
# must show up in stderr). A fault injected into a function that the tested path
# never calls proves nothing — the first attempt at this measurement fell for
# exactly that.
#
# Usage:  python3 tests/test_guard_crash_denies.py [path-to-hook]
# ============================================================================
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEFAULT_HOOK = REPO / "hooks" / "command-guard.py"

MARKER = "ARTIFICIAL_FAULT"

# Denied without any fault injected (self-protect path).
DANGEROUS = "echo broken > ~/.claude/settings.json"
# Allowed without any fault injected.
HARMLESS = "echo hello"


def _payload(tool, tool_input):
    return json.dumps({"session_id": "s", "hook_event_name": "PreToolUse",
                       "tool_name": tool, "tool_input": tool_input})


def _run(hook, stdin_text):
    with tempfile.TemporaryDirectory() as ov:
        env = dict(os.environ)
        env["CLAUDE_SUDO_OVERRIDES_DIR"] = ov
        env["CLAUDE_AUDIT_DIR"] = ov
        env["CLAUDE_HOOK_DEV_FLAG"] = ov + "/_none"
        p = subprocess.run(["python3", str(hook)], input=stdin_text,
                           capture_output=True, text=True, env=env, timeout=60)
        return p.returncode, (p.stderr or "")


def _with_fault(source, function_name):
    """Inject a raise at the very start of the named function."""
    marker = f"\ndef {function_name}("
    if marker not in source:
        raise AssertionError(f"function {function_name} not found")
    start = source.index(marker) + 1
    consumed = 0
    for line in source[start:].splitlines(keepends=True):
        consumed += len(line)
        if line.rstrip().endswith(":"):
            inject = f"    raise RuntimeError('{MARKER}')\n"
            return source[:start + consumed] + inject + source[start + consumed:]
    raise AssertionError(f"signature of {function_name} not parseable")


# (function, description, stdin payload) — each on a path that really calls it.
FAULT_SITES = [
    ("_normalize_obfuscation", "before every bash check",
     _payload("Bash", {"command": DANGEROUS})),
    ("command_hits_self_protect", "the barrier that really denies this command",
     _payload("Bash", {"command": DANGEROUS})),
    ("load_rules", "loading the rules (bash path)",
     _payload("Bash", {"command": DANGEROUS})),
    ("check_read_protection", "read protection path",
     _payload("Read", {"file_path": "/etc/shadow"})),
    ("hits_self_protect", "write path (Write/Edit)",
     _payload("Write", {"file_path": os.path.expanduser("~/.claude/settings.json"),
                        "content": "x"})),
]


def run_all(hook=None):
    hook = Path(hook or DEFAULT_HOOK)
    source = hook.read_text(encoding="utf-8")
    results = []

    with tempfile.TemporaryDirectory() as td:
        intact = os.path.join(td, "intact.py")
        Path(intact).write_text(source, encoding="utf-8")

        # --- regular behaviour must not change -------------------------------
        rc, _ = _run(intact, _payload("Bash", {"command": DANGEROUS}))
        results.append(("dangerous command still denied", rc == 2))
        rc, _ = _run(intact, _payload("Bash", {"command": HARMLESS}))
        results.append(("harmless command still allowed", rc == 0))
        rc, _ = _run(intact, _payload("Read", {"file_path": "/etc/shadow"}))
        results.append(("protected file still not read", rc == 2))

        # --- a failure of the guard must deny --------------------------------
        for function, description, payload in FAULT_SITES:
            path = os.path.join(td, f"fault_{function}.py")
            Path(path).write_text(_with_fault(source, function), encoding="utf-8")
            rc, err = _run(path, payload)
            results.append((f"fault in {function} is effective ({description})",
                            MARKER in err))
            results.append((f"fault in {function} denies", rc == 2))

        # --- the message tells the two cases apart ---------------------------
        path = os.path.join(td, "fault_message.py")
        Path(path).write_text(_with_fault(source, "command_hits_self_protect"),
                              encoding="utf-8")
        _, err_fault = _run(path, _payload("Bash", {"command": DANGEROUS}))
        results.append(("message says the guard stumbled",
                        "guard failure" in err_fault))
        _, err_normal = _run(intact, _payload("Bash", {"command": DANGEROUS}))
        results.append(("a normal denial does NOT carry that marker",
                        "guard failure" not in err_normal))

        # --- unreadable input ------------------------------------------------
        for name, text in (("unreadable input denied", "not json"),
                           ("empty input denied", ""),
                           ("truncated input denied", '{"tool_name":')):
            rc, _ = _run(intact, text)
            results.append((name, rc == 2))

    failed = 0
    for name, ok in results:
        print(f"{'PASS' if ok else 'FAIL'}  {name}")
        if not ok:
            failed += 1
    print(f"\nguard-crash-denies: {len(results) - failed}/{len(results)} passed")
    return failed


def test_guard_crash_denies():
    """pytest entry point: a return value would be IGNORED here.

    Without the assert pytest reports the file as passed no matter how
    the cases turn out. That is how a real failure stayed invisible.
    """
    assert run_all() == 0


if __name__ == "__main__":
    sys.exit(1 if run_all(
        sys.argv[1] if len(sys.argv) > 1 else None) else 0)
