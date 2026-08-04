# ============================================================================
# The project-control gate blocked over TEXT instead of over an ACTION.
#
# Two false positives, found within minutes of arming the gate:
#
# 1. The choke point searched EVERY string in the tool input, including the file
#    content about to be written. Any file that merely MENTIONS a control path
#    was blocked -- documentation, tests, measuring tools. The write target sits
#    in the path fields, never in the content.
#
# 2. The Bash side treated the program name behind an interpreter as a target.
#    Running a script that happens to live under a control directory is not
#    writing into it -- but as soon as any write word appeared anywhere in the
#    command, the call was refused.
#
# Both cost real work: the second one blocked the graph tool this project runs
# on every session.
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
TOOL = f"{HOME}/.claude/skills/some-skill/scripts/tool.py"
FOREIGN = "/tmp/foreign-project"

# (id, tool_name, tool_input, expected)
CASES = [
    # --- 1. content is not a target ---
    ("mention-in-content", "Write",
     {"file_path": "/tmp/doc.md", "content": f"see {FOREIGN}/.claude/settings.json"}, ALLOW),
    ("mention-in-replacement", "Edit",
     {"file_path": "/tmp/doc.md", "old_string": "a",
      "new_string": f"{FOREIGN}/.claude/hooks/x.py"}, ALLOW),
    ("mention-in-multiedit", "MultiEdit",
     {"file_path": "/tmp/doc.md",
      "edits": [{"old_string": "a", "new_string": f"{FOREIGN}/.mcp.json"}]}, ALLOW),

    # --- 2. an interpreter's program is not a target ---
    ("run-tool-under-control-dir", "Bash", {"command": f"python3 {TOOL} check"}, ALLOW),
    ("run-tool-after-delete", "Bash", {"command": f"rm -rf /tmp/x && python3 {TOOL} check"}, ALLOW),
    ("run-tool-after-redirect", "Bash", {"command": f"echo x > /tmp/y && python3 {TOOL} run"}, ALLOW),
    ("run-tool-with-switches", "Bash", {"command": f"rm /tmp/x; python3 -u {TOOL} check"}, ALLOW),

    # --- the protection must still hold ---
    ("still-blocks-settings-write", "Write",
     {"file_path": f"{FOREIGN}/.claude/settings.json", "content": "x"}, BLOCK),
    ("still-blocks-hook-redirect", "Bash",
     {"command": f"echo evil > {FOREIGN}/.claude/hooks/pre.py"}, BLOCK),
    ("still-blocks-overwriting-the-tool", "Bash",
     {"command": f"echo evil > {TOOL}"}, BLOCK),
    ("still-blocks-copy-into-skills", "Bash",
     {"command": f"cp /tmp/x {HOME}/.claude/skills/new/SKILL.md"}, BLOCK),
    ("still-blocks-mcp-write", "Write", {"file_path": f"{FOREIGN}/.mcp.json", "content": "x"}, BLOCK),
    ("still-blocks-interpreter-oneliner", "Bash",
     {"command": f"python3 -c \"open('{FOREIGN}/.claude/hooks/p.py','w').write('x')\""}, BLOCK),

    # --- counter-probe ---
    ("harmless-project-file", "Write", {"file_path": f"{FOREIGN}/note.md", "content": "x"}, ALLOW),
]


def _run(tool_name: str, tool_input: dict) -> int:
    with tempfile.TemporaryDirectory() as ov:
        env = dict(os.environ)
        env["CLAUDE_SUDO_OVERRIDES_DIR"] = ov
        env["CLAUDE_AUDIT_DIR"] = ov
        env["CLAUDE_HOOK_DEV_FLAG"] = ov + "/_none"
        p = subprocess.run(
            ["python3", str(HOOK)],
            input=json.dumps({"session_id": "false-positive-test",
                              "hook_event_name": "PreToolUse",
                              "tool_name": tool_name, "tool_input": tool_input}),
            capture_output=True, text=True, env=env,
        )
        return p.returncode


def run_all():
    return [(cid, expected, _run(t, i), _run(t, i) == expected)
            for cid, t, i, expected in CASES]


try:
    import pytest

    @pytest.mark.parametrize("cid,tool_name,tool_input,expected", CASES)
    def test_control_gate_false_positives(cid, tool_name, tool_input, expected):
        assert _run(tool_name, tool_input) == expected, cid

except ImportError:
    pass


if __name__ == "__main__":
    res = run_all()
    for cid, expected, rc, ok in res:
        tag = "PASS" if ok else "FAIL"
        exp = "allow" if expected == ALLOW else "block"
        got = "allow" if rc == ALLOW else ("block" if rc == BLOCK else f"rc={rc}")
        print(f"{tag}  {cid:36s} exp={exp:5s} got={got}")
    passed = sum(1 for *_, ok in res if ok)
    print(f"\nControl gate false positives: {passed}/{len(res)} passed  (hook: {HOOK})")
    raise SystemExit(0 if passed == len(res) else 1)
