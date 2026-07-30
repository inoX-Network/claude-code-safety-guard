# ============================================================================
# Environment variables must not be able to move the walls.
#
# The guard reads four path-determining variables (rules file, override
# directory, audit log, dev-mode flag). They were meant as test switches, but
# they are switches: whoever sets one decides where the guard reads its
# approvals from. And every protected path is written as "~/…", so redirecting
# HOME alone moves all of them at once.
#
# Both are reachable through a single line in a shell profile, which every new
# terminal reads.
#
# Two halves, tested separately:
#   1. HOME: the home directory must come from the password database. Testable
#      against any copy, because it holds everywhere.
#   2. The four variables: ignored at the production location, honoured by a
#      copy. Only the logic and the wiring are testable here — the production
#      half needs the hook to actually be installed, which a test cannot do.
#
# Usage:  python3 tests/test_env_cannot_move_the_walls.py [path-to-hook]
# Every case is a dry run. No command is executed, no profile file is touched.
# ============================================================================
import ast
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEFAULT_HOOK = REPO / "hooks" / "command-guard.py"
REAL_HOME = os.path.expanduser("~")

RULES = {
    "protected_reads": {
        "always_blocked_reads": ["/etc/shadow"],
        "require_override_1": ["~/.ssh/id_"],
        "always_allowed": [], "env_files_require_override_1": [],
    },
    "blocked_paths_write": ["~/.ssh", "/etc"],
    "blocked_patterns": [r"rm\s+-rf\s+/"],
}

# Denied while HOME is correct — must stay denied when HOME is redirected.
HOME_CASES = [
    ("Write", f"{REAL_HOME}/.claude/settings.json", "self-protection"),
    ("Write", f"{REAL_HOME}/.claude/.sudo-overrides/own.json", "override directory"),
    ("Bash", f"echo x > {REAL_HOME}/.claude/settings.json", "write redirect"),
    ("Bash", f"cat {REAL_HOME}/.ssh/id_rsa", "read guard"),
]


def _run(hook, tool, value, extra_env, rules_path=None):
    with tempfile.TemporaryDirectory() as ov:
        env = dict(os.environ)
        env["CLAUDE_SUDO_OVERRIDES_DIR"] = ov
        env["CLAUDE_AUDIT_DIR"] = ov
        env["CLAUDE_HOOK_DEV_FLAG"] = ov + "/_none"
        if rules_path:
            env["CLAUDE_SECURITY_RULES"] = rules_path
        env.update(extra_env)
        if tool == "Bash":
            payload = {"tool_name": "Bash", "tool_input": {"command": value}}
        else:
            payload = {"tool_name": tool,
                       "tool_input": {"file_path": value, "content": "x"}}
        payload.update({"session_id": "s", "hook_event_name": "PreToolUse"})
        p = subprocess.run(["python3", str(hook)], input=json.dumps(payload),
                           capture_output=True, text=True, env=env, timeout=60)
        return p.returncode == 2


def test_env_cannot_move_the_walls(hook=None):
    hook = Path(hook or DEFAULT_HOOK)
    results = []

    # --- 1. HOME ----------------------------------------------------------
    with tempfile.TemporaryDirectory() as fake_home:
        for tool, value, name in HOME_CASES:
            correct = _run(hook, tool, value, {})
            redirected = _run(hook, tool, value, {"HOME": fake_home})
            results.append((f"{name}: denied with HOME correct", correct))
            results.append((f"{name}: still denied with HOME redirected", redirected))

    # --- 2. logic and wiring ---------------------------------------------
    spec = importlib.util.spec_from_file_location("guard_under_test", hook)
    guard = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(guard)

    missing = [n for n in ("_is_production", "_env", "_ENV_ALLOWED",
                           "_PRODUCTION_HOOK", "_real_home", "_HOME")
               if not hasattr(guard, n)]
    if missing:
        results.append((f"the fix is present ({', '.join(missing)} missing)", False))
    else:
        is_production_file = False
        try:
            is_production_file = Path(hook).resolve() == guard._PRODUCTION_HOOK.resolve()
        except OSError:
            pass
        results.append(("production location recognised correctly",
                        guard._is_production() is is_production_file))

        keep = guard._PRODUCTION_HOOK
        try:
            guard._PRODUCTION_HOOK = Path(hook)
            results.append(("the same file counts as production",
                            guard._is_production() is True))
            guard._PRODUCTION_HOOK = Path("/nowhere/command-guard.py")
            results.append(("another location does not",
                            guard._is_production() is False))
        finally:
            guard._PRODUCTION_HOOK = keep

        os.environ["CLAUDE_TEST_VALUE"] = "set"
        guard._ENV_ALLOWED = True
        results.append(("outside production the variable is read",
                        guard._env("CLAUDE_TEST_VALUE") == "set"))
        guard._ENV_ALLOWED = False
        results.append(("at the production location it yields nothing",
                        guard._env("CLAUDE_TEST_VALUE") is None))
        guard._ENV_ALLOWED = True
        del os.environ["CLAUDE_TEST_VALUE"]

        # No call site may reach past the helper.
        source = hook.read_text(encoding="utf-8")
        lines = source.splitlines()
        direct = []
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                    and node.func.attr == "get" \
                    and isinstance(node.func.value, ast.Attribute) \
                    and node.func.value.attr == "environ":
                if "_ENV_ALLOWED" not in lines[node.lineno - 1]:
                    direct.append(node.lineno)
        results.append((f"no direct environment access outside the helper"
                        f"{' (lines ' + str(direct) + ')' if direct else ''}",
                        not direct))
        results.append(("no home lookups through the environment",
                        "Path.home()" not in source.split("_HOME = _real_home()", 1)[1]))

    failed = 0
    for name, ok in results:
        print(f"{'PASS' if ok else 'FAIL'}  {name}")
        if not ok:
            failed += 1
    print(f"\nenv-cannot-move-the-walls: {len(results) - failed}/{len(results)} passed")
    return failed


if __name__ == "__main__":
    sys.exit(1 if test_env_cannot_move_the_walls(
        sys.argv[1] if len(sys.argv) > 1 else None) else 0)
