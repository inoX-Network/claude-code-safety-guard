# ============================================================================
# An inline one-liner colours ITS OWN segment, not the whole line.
#
# The interpreter branch exists because inline code is opaque to shell
# tokenisation: a protected path inside open("...") never starts a token, so it
# has to be matched as a substring. That is correct — but the check ran against
# the WHOLE command as soon as a one-liner appeared anywhere on the line. A path
# that merely sat in an echo next to it brought the line down.
#
# Measured against a real audit log: 47 refusals of this shape across 33
# different sessions — no single test run inflating the count. Nearly all of
# them are status questions: "is the override active?", "what is in the
# settings file?". The guard was blocking the act of checking whether a grant
# exists.
#
# THIS LOOSENS THE SHARPEST PART OF THE GUARD, so the refusal half of this file
# is the one that matters. The dangerous case is first:
#
#   split_segments also splits INSIDE quotes. `python3 -c "import os;
#   os.remove(path)"` breaks apart at the semicolon — the first piece carries
#   the one-liner without the path, the second the path without a recognisable
#   one-liner. Checking each segment naively lets exactly that through. The fix
#   appends segments until the quotes balance again; a mutation test confirms
#   that removing that loop drops four refusals.
# ============================================================================
import json
import os
import subprocess
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
HOOK = Path(os.environ.get("GUARD_HOOK") or (REPO / "hooks" / "command-guard.py"))
HOME = os.path.expanduser("~")

RULES = {
    "protected_reads": {"always_blocked_reads": [], "require_override_1": ["~/.ssh/id_"],
                        "always_allowed": ["~/.ssh/*.pub"],
                        "env_files_require_override_1": []},
    "blocked_paths_write": ["/etc", "~/.ssh"],
    "blocked_patterns": [], "blocked_git_ops": [],
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
        env["CLAUDE_HOOK_DEV_FLAG"] = str(tmp / "_no_window")
        env["CLAUDE_GUARD_CONFIG"] = str(tmp / "_no_config.json")
        p = subprocess.run(
            ["python3", str(HOOK)],
            input=json.dumps({"session_id": "inline-code-segment-test",
                              "tool_name": "Bash",
                              "tool_input": {"command": command}}),
            capture_output=True, text=True, env=env)
    return p.returncode == 2, f"exit {p.returncode}: {' '.join(p.stderr.split())[:130]}"


def _stays_free(command: str) -> tuple[bool, str]:
    blocked, detail = _blocks(command)
    return not blocked, detail


# --- what must STAY refused. A miss here is a way in, not a nuisance. --------

def check_one_liner_with_semicolon_is_refused():
    """THE trap: the split lands inside the quotes, path in the second piece."""
    return _blocks(
        f"python3 -c \"import os; os.remove('{HOME}/.claude/settings.json')\"")


def check_one_liner_with_several_statements_is_refused():
    return _blocks(
        f"python3 -c \"import os, sys; x = 1; os.remove('{HOME}/.claude/hooks/x')\"")


def check_one_liner_writing_the_settings_file_is_refused():
    return _blocks(f"python3 -c \"open('{HOME}/.claude/settings.json','w').write('x')\"")


def check_one_liner_in_the_second_segment_is_refused():
    return _blocks(
        f"echo start; python3 -c \"open('{HOME}/.claude/settings.json','w').write('x')\"")


def check_other_interpreter_same_intent_is_refused():
    return _blocks(
        f"node -e \"require('fs').writeFileSync('{HOME}/.claude/settings.json','x')\"")


def check_one_liner_reading_a_private_key_is_refused():
    return _blocks(f"python3 -c \"print(open('{HOME}/.ssh/id_rsa').read())\"")


def check_one_liner_after_a_harmless_segment_is_refused():
    return _blocks(
        f"ls /tmp && python3 -c \"open('{HOME}/.claude/settings.json','w').write('x')\"")


# --- what must run FREE. These are the measured false positives. ------------

def check_status_listing_next_to_a_one_liner_stays_free():
    """The most common measured shape: asking whether a grant exists."""
    return _stays_free(f"python3 -c \"print(1)\"; ls -1 {HOME}/.claude/")


def check_protected_path_as_plain_text_stays_free():
    return _stays_free(f"python3 -c \"print(1)\"; echo {HOME}/.claude/hooks")


def check_cd_and_grep_next_to_a_one_liner_stays_free():
    return _stays_free(f"python3 -c \"print(1)\"; cd {HOME}/.claude && grep -c x file")


def check_public_key_in_the_one_liner_stays_free():
    """always_allowed must still be honoured inside inline code."""
    return _stays_free(f"python3 -c \"print(open('{HOME}/.ssh/id_rsa.pub').read())\"")


def check_one_liner_without_any_protected_path_stays_free():
    return _stays_free("python3 -c \"print(1)\"; echo done")


CASES = [
    ("one liner with semicolon is refused", check_one_liner_with_semicolon_is_refused),
    ("one liner with several statements is refused", check_one_liner_with_several_statements_is_refused),
    ("one liner writing the settings file is refused", check_one_liner_writing_the_settings_file_is_refused),
    ("one liner in the second segment is refused", check_one_liner_in_the_second_segment_is_refused),
    ("other interpreter same intent is refused", check_other_interpreter_same_intent_is_refused),
    ("one liner reading a private key is refused", check_one_liner_reading_a_private_key_is_refused),
    ("one liner after a harmless segment is refused", check_one_liner_after_a_harmless_segment_is_refused),
    ("status listing next to a one liner stays free", check_status_listing_next_to_a_one_liner_stays_free),
    ("protected path as plain text stays free", check_protected_path_as_plain_text_stays_free),
    ("cd and grep next to a one liner stays free", check_cd_and_grep_next_to_a_one_liner_stays_free),
    ("public key in the one liner stays free", check_public_key_in_the_one_liner_stays_free),
    ("one liner without any protected path stays free", check_one_liner_without_any_protected_path_stays_free),
]

try:
    import pytest

    @pytest.mark.parametrize("name,fn", CASES)
    def test_inline_code_segment(name, fn):
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
