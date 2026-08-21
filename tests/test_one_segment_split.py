# ============================================================================
# One split, not six.
#
# Six places used to cut a command line into segments, each with its own copy of
# the same pattern. On 2026-08-20 three of them did not know the newline, and
# the drift ran in both directions: transfers onto a protected server path went
# through 39 times, while copy commands after a line break were refused.
#
# Bringing all six to the same state treated the symptom. These tests cover the
# cure — one function, six callers — from the two sides that can actually break:
#
#   1. The KEEP form. Two callers reassemble the line afterwards and need the
#      separators back in the result. Drop the keep and the separators vanish,
#      the next segment glues onto the previous one, and a protected path that
#      sat at the end of its segment loses the boundary that identified it.
#      Measured: `chmod 700 ~/.claude/bin;echo x` walks FREE without keep.
#      That is self-protection, so this is not a cosmetic argument.
#
#   2. The seventh copy. Behaviour tests cannot see a refactoring — a copy of
#      the pattern behaves identically on the day it is written. It only drifts
#      later. So the structure itself is asserted: the separator pattern lives
#      in exactly two constants and nowhere else.
#
# The structural test catches the realistic case — someone copies the existing
# line. It cannot catch a hand-rolled split that spells the separators
# differently. That is a known limit, not an oversight.
# ============================================================================
import json
import os
import subprocess
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
HOOK = Path(os.environ.get("GUARD_HOOK") or (REPO / "hooks" / "command-guard.py"))

RULES = {
    "protected_reads": {"always_blocked_reads": [], "require_override_1": [],
                        "always_allowed": [], "env_files_require_override_1": []},
    "blocked_paths_write": [], "blocked_patterns": [], "blocked_git_ops": [],
    "protected_git_branches": [], "blocked_bash_patterns_force_push": [],
    "allowed_sudo": [], "owner_only_commands": [], "require_confirmation": [],
}


def _blocks(command: str) -> tuple[bool, str]:
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        (tmp / "rules.json").write_text(json.dumps(RULES), encoding="utf-8")
        env = dict(os.environ)
        env["CLAUDE_SECURITY_RULES"] = str(tmp / "rules.json")
        env["CLAUDE_SUDO_OVERRIDES_DIR"] = str(tmp / "ov")
        env["CLAUDE_AUDIT_DIR"] = str(tmp / "audit")
        # No dev window: self-protection must answer for real, even when the
        # owner happens to have one open while the suite runs.
        env["CLAUDE_HOOK_DEV_FLAG"] = str(tmp / "_no_window")
        env["CLAUDE_GUARD_CONFIG"] = str(tmp / "_no_config.json")
        p = subprocess.run(
            ["python3", str(HOOK)],
            input=json.dumps({"session_id": "one-segment-split-test",
                              "tool_name": "Bash",
                              "tool_input": {"command": command}}),
            capture_output=True, text=True, env=env)
    return p.returncode == 2, f"exit {p.returncode}: {' '.join(p.stderr.split())[:150]}"


def _stays_free(command: str) -> tuple[bool, str]:
    blocked, detail = _blocks(command)
    return not blocked, detail


# --- the keep form: separators must survive the reassembly ------------------
# Each of these has a protected path at the END of its segment, followed by a
# separator that carries no space. Without the separators in the result the
# next segment glues on, the path boundary is lost, and the write runs free.

def check_semicolon_without_space():
    """Measured case: free without keep, refused with it."""
    return _blocks("chmod 700 ~/.claude/bin;echo done")


def check_and_chain_without_space():
    return _blocks("chmod 700 ~/.claude/bin&&echo done")


def check_newline_after_the_path():
    """The newline is a separator too — that was the 2026-08-20 hole."""
    return _blocks("chmod 700 ~/.claude/bin\necho done")


def check_copy_command_in_front():
    """A copy in an earlier segment is what puts the reassembly to work."""
    return _blocks("cp /tmp/a /tmp/b;chmod 700 ~/.claude/bin;echo done")


# --- the other side: the gate must not start firing on everything -----------

def check_path_inside_the_segment_still_blocks():
    """Counter-check: with the path mid-segment the boundary was never at risk,
    so this must block with and without the keep. It is here to prove the four
    cases above measure the SEPARATOR and not merely 'chmod on bin blocks'."""
    return _blocks("chmod 700 ~/.claude/bin/helper;echo done")


def check_harmless_chain_stays_free():
    return _stays_free("echo hello;echo world")


def check_copy_source_is_still_not_a_write_target():
    """The reason _without_copy_sources exists at all: reading the guard's own
    file into a working copy is not an attack on it."""
    return _stays_free("cp ~/.claude/bin/helper /tmp/working-copy")


# --- the seventh copy must not happen ---------------------------------------

def check_separator_pattern_lives_in_one_place():
    """The pattern may appear in exactly two constants — the plain and the
    keeping form — and nowhere else. Anything more is copy number seven."""
    source = HOOK.read_text(encoding="utf-8")
    hits = [line.strip() for line in source.splitlines() if r"[;|\n]" in line]
    if len(hits) != 2:
        return False, f"separator pattern on {len(hits)} lines: {hits}"
    named = [h for h in hits if h.startswith("_SEGMENT_RE")
             or h.startswith("_SEGMENT_KEEP_RE")]
    if len(named) != 2:
        return False, f"pattern outside the two constants: {hits}"
    return True, ""


def check_every_caller_uses_the_shared_function():
    """Six call sites, one definition — counted, so a caller cannot quietly
    grow its own split again."""
    source = HOOK.read_text(encoding="utf-8")
    calls = source.count("split_segments(")
    definitions = source.count("def split_segments(")
    if definitions != 1:
        return False, f"{definitions} definitions of split_segments"
    # 6 callers + 1 definition line
    if calls < 7:
        return False, f"only {calls - 1} call sites left — a caller went its own way"
    return True, ""


CASES = [
    ("semicolon without space keeps the boundary", check_semicolon_without_space),
    ("and-chain without space keeps the boundary", check_and_chain_without_space),
    ("newline after the path keeps the boundary", check_newline_after_the_path),
    ("copy command in front", check_copy_command_in_front),
    ("path inside the segment still blocks", check_path_inside_the_segment_still_blocks),
    ("harmless chain stays free", check_harmless_chain_stays_free),
    ("copy source is not a write target", check_copy_source_is_still_not_a_write_target),
    ("separator pattern lives in one place", check_separator_pattern_lives_in_one_place),
    ("every caller uses the shared function", check_every_caller_uses_the_shared_function),
]

try:
    import pytest

    @pytest.mark.parametrize("name,fn", CASES)
    def test_one_segment_split(name, fn):
        ok, detail = fn()
        assert ok, f"{name}: {detail}"

except ImportError:
    pass


if __name__ == "__main__":
    failures = 0
    for name, fn in CASES:
        ok, detail = fn()
        failures += not ok
        print(f"{'PASS' if ok else 'FAIL'}  {name}")
        if not ok:
            print(f"      {detail}")
    raise SystemExit(0 if not failures else 1)
