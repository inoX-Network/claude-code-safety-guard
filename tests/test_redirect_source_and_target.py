# ============================================================================
# A redirect writes where the arrow points. What stands before it is read.
#
# This file exists because of a HOLE, found while building a false-positive
# fix. Source/target separation for copies goes by position — the last argument
# is the target. Append a harmless output redirect and the last argument is the
# log file, so the protected path slides into the source role and is dropped
# from the check as a read:
#
#     cp /tmp/a <protected>              -> refused
#     cp /tmp/a <protected> > log.txt    -> ran free
#
# That hits self-protection, the one place where no override helps. The control
# case (same copy without the redirect) is in the refusal half below, because a
# fix here must not "work" by making both run.
#
# The same treatment removes a measured false positive: a checksum over a
# protected file whose OUTPUT goes to the scratch area was refused, although
# only the scratch area is written. 5 such refusals across 5 sessions —
# small, but nearly all of it is work ON the guard itself: comparing two
# versions, pulling a working copy, fetching a config from a server.
#
# One line in the fix is load-bearing and was missing at first: with NO
# redirect present, nothing may change. Without it a cd segment collapsed to an
# empty string, and two holes closed earlier the same day stood open again.
# The refusal half of a DIFFERENT test list caught that — not this one.
# ============================================================================
import json
import os
import subprocess
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
HOOK = Path(os.environ.get("GUARD_HOOK") or (REPO / "hooks" / "command-guard.py"))
HOME = os.path.expanduser("~")
GUARD = f"{HOME}/.claude/hooks/command-guard.py"

RULES = {
    "protected_reads": {"always_blocked_reads": [], "require_override_1": [],
                        "always_allowed": [], "env_files_require_override_1": []},
    "blocked_paths_write": ["/etc", "/bin", "~/.ssh"],
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
            input=json.dumps({"session_id": "redirect-target-test",
                              "tool_name": "Bash",
                              "tool_input": {"command": command}}),
            capture_output=True, text=True, env=env)
    return p.returncode == 2, f"exit {p.returncode}: {' '.join(p.stderr.split())[:130]}"


def _stays_free(command: str) -> tuple[bool, str]:
    blocked, detail = _blocks(command)
    return not blocked, detail


# --- what must STAY refused. The first two are THE hole. --------------------

def check_copy_onto_a_guard_file_with_redirect_is_refused():
    """The hole: the appended redirect used to hide the copy target."""
    return _blocks(f"cp /tmp/a {GUARD} > /tmp/log.txt")


def check_copy_onto_a_guard_file_without_redirect_is_refused():
    """Control case — a fix must not make BOTH run."""
    return _blocks(f"cp /tmp/a {GUARD}")


def check_redirect_onto_a_protected_file_is_refused():
    return _blocks("echo x > /etc/profile.d/x.sh")


def check_appending_redirect_onto_a_protected_file_is_refused():
    return _blocks("date >> /etc/profile.d/x.sh")


def check_protected_target_behind_the_arrow_harmless_source_is_refused():
    return _blocks("cat /tmp/x > /etc/hosts")


def check_delete_with_output_redirect_is_refused():
    return _blocks("rm -f /etc/hosts > /tmp/log.txt")


def check_write_verb_before_the_arrow_still_checked():
    return _blocks("cp /tmp/a /bin/sh > /tmp/log.txt")


# --- what must run FREE. These are the measured false positives. ------------

def check_checksum_of_a_protected_file_into_scratch_stays_free():
    return _stays_free(f"sha256sum {GUARD} > /tmp/sum.txt")


def check_diff_of_two_versions_into_scratch_stays_free():
    return _stays_free(f"diff {GUARD} /tmp/ref.py > /tmp/delta.txt")


def check_working_copy_via_cat_stays_free():
    return _stays_free(f"cat {GUARD} > /tmp/copy.py")


def check_line_count_appended_to_a_report_stays_free():
    return _stays_free(f"wc -l {GUARD} >> /tmp/report.txt")


def check_redirect_without_any_protected_path_stays_free():
    return _stays_free("echo hello > /tmp/x.txt")


CASES = [
    ("copy onto a guard file with redirect is refused", check_copy_onto_a_guard_file_with_redirect_is_refused),
    ("copy onto a guard file without redirect is refused", check_copy_onto_a_guard_file_without_redirect_is_refused),
    ("redirect onto a protected file is refused", check_redirect_onto_a_protected_file_is_refused),
    ("appending redirect onto a protected file is refused", check_appending_redirect_onto_a_protected_file_is_refused),
    ("protected target behind the arrow harmless source is refused", check_protected_target_behind_the_arrow_harmless_source_is_refused),
    ("delete with output redirect is refused", check_delete_with_output_redirect_is_refused),
    ("write verb before the arrow still checked", check_write_verb_before_the_arrow_still_checked),
    ("checksum of a protected file into scratch stays free", check_checksum_of_a_protected_file_into_scratch_stays_free),
    ("diff of two versions into scratch stays free", check_diff_of_two_versions_into_scratch_stays_free),
    ("working copy via cat stays free", check_working_copy_via_cat_stays_free),
    ("line count appended to a report stays free", check_line_count_appended_to_a_report_stays_free),
    ("redirect without any protected path stays free", check_redirect_without_any_protected_path_stays_free),
]

try:
    import pytest

    @pytest.mark.parametrize("name,fn", CASES)
    def test_redirect_source_and_target(name, fn):
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
