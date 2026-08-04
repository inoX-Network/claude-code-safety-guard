# ============================================================================
# Self-protection compared paths lexically — so a RELATIVE target walked past it.
#
# `cp x hooks/command-guard.py` from inside ~/.claude hits exactly the same file
# as `cp x ~/.claude/hooks/command-guard.py`, but the relative spelling does not
# contain the protected absolute path literally. Measured: the absolute and
# tilde forms are refused, the relative ones go through — via cp, via redirect
# and via the Write tool.
#
# How it surfaced: not from the suite, but from a control probe after closing
# the dev window. The very command that had needed the window ran through
# unchanged afterwards — meaning it had never needed the window at all.
#
# Second defect in the same family: the interpreter-inline detection paired
# "some interpreter appears" with "some inline switch appears" anywhere in the
# command, without the two belonging together. A `mkdir -p` before a tool call
# was enough to classify the whole command as inline code.
#
# Pure dry run: only decisions are inspected. Nothing is written or created.
# ============================================================================
import json
import os
import subprocess
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
HOOK = Path(os.environ.get("GUARD_HOOK") or (REPO / "hooks" / "command-guard.py"))

ALLOW = 0
BLOCK = 2

HOME = str(Path.home())
CLAUDE = f"{HOME}/.claude"
# A builtin self-protect path — same on every installation.
TARGET_ABS = f"{CLAUDE}/hooks/command-guard.py"

# (id, cwd, tool_name, tool_input, expected)
CASES = [
    # --- the spellings that already worked ---
    ("abs-cp", CLAUDE, "Bash", {"command": f"cp /tmp/x {TARGET_ABS}"}, BLOCK),
    ("tilde-cp", CLAUDE, "Bash", {"command": "cp /tmp/x ~/.claude/hooks/command-guard.py"}, BLOCK),
    ("abs-write", CLAUDE, "Write", {"file_path": TARGET_ABS, "content": "x"}, BLOCK),

    # --- the same file, spelled relative to the working directory ---
    ("rel-cp", CLAUDE, "Bash", {"command": "cp /tmp/x hooks/command-guard.py"}, BLOCK),
    ("rel-dot-cp", CLAUDE, "Bash", {"command": "cp /tmp/x ./hooks/command-guard.py"}, BLOCK),
    ("rel-redirect", CLAUDE, "Bash", {"command": "echo evil > hooks/command-guard.py"}, BLOCK),
    ("rel-tee", CLAUDE, "Bash", {"command": "echo evil | tee hooks/command-guard.py"}, BLOCK),
    ("rel-mv", CLAUDE, "Bash", {"command": "mv /tmp/x hooks/command-guard.py"}, BLOCK),
    ("rel-write", CLAUDE, "Write", {"file_path": "hooks/command-guard.py", "content": "x"}, BLOCK),
    ("rel-edit", CLAUDE, "Edit",
     {"file_path": "hooks/command-guard.py", "old_string": "a", "new_string": "b"}, BLOCK),
    ("rel-detour", f"{CLAUDE}/hooks", "Bash",
     {"command": "cp /tmp/x ../hooks/command-guard.py"}, BLOCK),

    # --- self-protection ALONE, without the project-control rule helping ---
    # ~/.claude/rules is self-protected but matches none of the project-control
    # patterns (settings/hooks/agents/skills/commands/.mcp.json). Without these
    # cases the relative-path result above would be credited to the wrong rule:
    # the first mutation probe showed exactly that.
    ("selfonly-rel-cp", CLAUDE, "Bash", {"command": "cp /tmp/x rules/probe.md"}, BLOCK),
    ("selfonly-rel-redirect", CLAUDE, "Bash", {"command": "echo x > rules/probe.md"}, BLOCK),
    ("selfonly-rel-tee", CLAUDE, "Bash", {"command": "echo x | tee rules/probe.md"}, BLOCK),
    ("selfonly-rel-write", CLAUDE, "Write", {"file_path": "rules/probe.md", "content": "x"}, BLOCK),
    ("selfonly-abs-cp", CLAUDE, "Bash", {"command": f"cp /tmp/x {CLAUDE}/rules/probe.md"}, BLOCK),
    # ...and the same spelling elsewhere stays free.
    ("selfonly-elsewhere", "/tmp", "Bash", {"command": "cp /tmp/x rules/probe.md"}, ALLOW),

    # --- the cd happens INSIDE the command, so the shell is not there yet ---
    # This is the live case: a session rarely sits in the protected directory
    # already; it gets there with `cd X && …`. At check time that cd has not run,
    # so the reported working directory is useless — the command itself has to be
    # read. The guard already does this for git commits.
    ("cd-then-cp", "/tmp", "Bash",
     {"command": f"cd {CLAUDE} && cp /tmp/x rules/probe.md"}, BLOCK),
    ("cd-then-redirect", "/tmp", "Bash",
     {"command": f"cd {CLAUDE} && echo x > rules/probe.md"}, BLOCK),
    ("cd-tilde-then-cp", "/tmp", "Bash",
     {"command": "cd ~/.claude && cp /tmp/x rules/probe.md"}, BLOCK),
    ("cd-then-cp-hooks", "/tmp", "Bash",
     {"command": f"cd {CLAUDE} && cp /tmp/x hooks/command-guard.py"}, BLOCK),
    # ...and a cd somewhere harmless keeps the same spelling free.
    ("cd-elsewhere-then-cp", HOME, "Bash",
     {"command": "cd /tmp && cp /tmp/x rules/probe.md"}, ALLOW),
    ("cd-then-harmless", "/tmp", "Bash",
     {"command": f"cd {CLAUDE} && cp /tmp/x notes/todo.md"}, ALLOW),

    # --- counter-probe: the SAME spelling from elsewhere is harmless ---
    # /tmp/hooks/command-guard.py is not a protected path. If this one turns red,
    # the fix blocks by name instead of by location.
    ("same-spelling-elsewhere", "/tmp", "Bash",
     {"command": "cp /tmp/x hooks/command-guard.py"}, ALLOW),
    ("harmless-relative", CLAUDE, "Bash", {"command": "cp /tmp/x notes/todo.md"}, ALLOW),
    ("harmless-relative-write", CLAUDE, "Write",
     {"file_path": "notes/todo.md", "content": "x"}, ALLOW),

    # --- interpreter-inline detection must not fire on an unrelated switch ---
    ("mkdir-switch-before-tool", HOME, "Bash",
     {"command": f"mkdir -p /tmp/a && python3 {CLAUDE}/skills/s/tool.py check"}, ALLOW),
    ("tar-switch-before-tool", HOME, "Bash",
     {"command": f"tar -xzf /tmp/a.tgz && python3 {CLAUDE}/skills/s/tool.py run"}, ALLOW),
    # ...but a real inline one-liner naming a protected path still blocks.
    ("real-inline-oneliner", HOME, "Bash",
     {"command": f"python3 -c \"open('{TARGET_ABS}','w').write('x')\""}, BLOCK),
]


def _run(cwd: str, tool_name: str, tool_input: dict) -> int:
    with tempfile.TemporaryDirectory() as ov:
        env = dict(os.environ)
        env["CLAUDE_SUDO_OVERRIDES_DIR"] = ov
        env["CLAUDE_AUDIT_DIR"] = ov
        env["CLAUDE_HOOK_DEV_FLAG"] = ov + "/_none"
        payload = {"session_id": "relative-target-test", "hook_event_name": "PreToolUse",
                   "tool_name": tool_name, "tool_input": tool_input, "cwd": cwd}
        p = subprocess.run(["python3", str(HOOK)], input=json.dumps(payload),
                           capture_output=True, text=True, env=env, cwd=cwd)
        return p.returncode


def run_all():
    return [(cid, expected, rc, rc == expected)
            for cid, cwd, t, i, expected in CASES
            for rc in [_run(cwd, t, i)]]


try:
    import pytest

    @pytest.mark.parametrize("cid,cwd,tool_name,tool_input,expected", CASES)
    def test_relative_write_targets(cid, cwd, tool_name, tool_input, expected):
        assert _run(cwd, tool_name, tool_input) == expected, cid

except ImportError:
    pass


if __name__ == "__main__":
    res = run_all()
    for cid, expected, rc, ok in res:
        tag = "PASS" if ok else "FAIL"
        exp = "allow" if expected == ALLOW else "block"
        got = "allow" if rc == ALLOW else ("block" if rc == BLOCK else f"rc={rc}")
        print(f"{tag}  {cid:28s} exp={exp:5s} got={got}")
    passed = sum(1 for *_, ok in res if ok)
    print(f"\nRelative write targets: {passed}/{len(res)} passed  (hook: {HOOK})")
    raise SystemExit(0 if passed == len(res) else 1)
