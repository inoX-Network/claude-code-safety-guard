# ============================================================================
# Read protection reached only ONE tool branch.
#
# check_read_protection was wired into the Read branch (and, in token form, into
# the Bash branch). Write/Edit/MultiEdit/NotebookEdit and every MCP tool never
# called it. A path that is read-protected but not write-protected was therefore
# fully exposed through those branches -- and overwriting a credential file is
# worse than reading it: whoever can replace credentials never needs to read them.
#
# The fix is NOT "call it in the other branches too" -- that is per-branch wiring
# again, and the next new branch gets forgotten. The fix is a single choke point
# in main() that every file-touching tool passes before branch-specific logic runs.
#
# Bash is deliberately exempt: it has its own, stronger tokenising check
# (command_hits_protected_read).
#
# Pure dry run: only the decision is inspected. Nothing is read, written or created.
# ============================================================================
import json
import os
import subprocess
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
# GUARD_HOOK lets the same suite run against a second copy of the guard
# (the German downstream fassung) instead of a forked test file.
HOOK = Path(os.environ.get("GUARD_HOOK") or (REPO / "hooks" / "command-guard.py"))
EXAMPLE_RULES = REPO / "security-rules.example.json"

ALLOW = 0
BLOCK = 2

HARD = "/tmp/guard-coverage-hard/f"     # always_blocked_reads -> no override lifts it
GATED = "/tmp/guard-coverage-gated/f"   # require_override_1   -> level 1 lifts it
PLAIN = "/tmp/guard-coverage-plain/f"   # unprotected control

# Every file-touching branch. Bash has its own check and is out of scope here.
TOOLS = ["Read", "Write", "Edit", "MultiEdit", "NotebookEdit",
         "mcp__filesystem__read_file"]


def _make_rules() -> str:
    """Rules where the protected paths are read-protected ONLY.

    blocked_paths_write is emptied on purpose: if the write guard covered these
    paths, a green Write case would prove nothing about the read protection.
    """
    rules = json.loads(EXAMPLE_RULES.read_text(encoding="utf-8"))
    rules["protected_reads"] = {
        "always_blocked_reads": ["/tmp/guard-coverage-hard"],
        "require_override_1": ["/tmp/guard-coverage-gated"],
        "always_allowed": [],
        "env_files_require_override_1": [],
    }
    rules["blocked_paths_write"] = []
    rules["blocked_paths"] = []
    tf = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
    json.dump(rules, tf)
    tf.close()
    return tf.name


def _tool_input(tool: str, path: str) -> dict:
    if tool == "Read":
        return {"file_path": path}
    if tool == "Write":
        return {"file_path": path, "content": "x"}
    if tool == "Edit":
        return {"file_path": path, "old_string": "a", "new_string": "b"}
    if tool == "MultiEdit":
        return {"file_path": path, "edits": [{"old_string": "a", "new_string": "b"}]}
    if tool == "NotebookEdit":
        return {"notebook_path": path, "new_source": "x"}
    return {"path": path}          # MCP: the field name differs per server


def _run(tool: str, path: str, rules_path: str, override_level: int | None = None) -> int:
    payload = {
        "session_id": "read-coverage-test",
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "tool_input": _tool_input(tool, path),
    }
    with tempfile.TemporaryDirectory() as ov:
        if override_level is not None:
            expires = (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat()
            (Path(ov) / "coverage-test.json").write_text(json.dumps({
                "override_level": override_level,
                "task": "read protection coverage test",
                "confirmed": True,
                "expires_at": expires,
                "grants": {"additional_sudo": [], "allowed_paths": []},
            }), encoding="utf-8")
        env = dict(os.environ)
        env["CLAUDE_SECURITY_RULES"] = rules_path
        env["CLAUDE_SUDO_OVERRIDES_DIR"] = ov
        env["CLAUDE_AUDIT_DIR"] = ov
        env["CLAUDE_HOOK_DEV_FLAG"] = ov + "/_none"
        p = subprocess.run(
            ["python3", str(HOOK)],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            env=env,
        )
        return p.returncode


def _cases():
    """(id, tool, path, override_level, expected) for every branch.

    The PLAIN case is the counter-probe: it must stay green before AND after the
    fix. Without it a red MCP case could just as well mean the MCP policy blocked
    the call -- red for the wrong reason proves nothing.
    """
    out = []
    for tool in TOOLS:
        short = tool.replace("mcp__filesystem__", "mcp:")
        out.append((f"{short}-hard", tool, HARD, None, BLOCK))
        out.append((f"{short}-gated-no-override", tool, GATED, None, BLOCK))
        out.append((f"{short}-gated-override-1", tool, GATED, 1, ALLOW))
        out.append((f"{short}-plain", tool, PLAIN, None, ALLOW))
        # No override lifts always_blocked_reads -- not even level 3.
        out.append((f"{short}-hard-override-3", tool, HARD, 3, BLOCK))
    return out


CASES = _cases()


def run_all():
    rules = _make_rules()
    results = []
    try:
        for cid, tool, path, level, expected in CASES:
            rc = _run(tool, path, rules, level)
            results.append((cid, path, expected, rc, rc == expected))
    finally:
        try:
            os.unlink(rules)
        except OSError:
            pass
    return results


try:
    import pytest

    _RULES = _make_rules()

    @pytest.mark.parametrize("cid,tool,path,level,expected", CASES)
    def test_read_protection_coverage(cid, tool, path, level, expected):
        assert _run(tool, path, _RULES, level) == expected, f"{cid}: {tool} {path!r}"

except ImportError:
    pass


if __name__ == "__main__":
    res = run_all()
    for cid, path, expected, rc, ok in res:
        tag = "PASS" if ok else "FAIL"
        exp = "allow" if expected == ALLOW else "block"
        got = "allow" if rc == ALLOW else ("block" if rc == BLOCK else f"rc={rc}")
        print(f"{tag}  {cid:34s} exp={exp:5s} got={got:5s}  {path}")
    passed = sum(1 for *_, ok in res if ok)
    print(f"\nRead protection coverage: {passed}/{len(res)} passed  (hook: {HOOK})")
    raise SystemExit(0 if passed == len(res) else 1)
