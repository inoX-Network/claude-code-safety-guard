# ============================================================================
# A write in ONE segment does not make a protected path in ANOTHER its target.
#
# The read guard has drawn this line for a while: it asks, per segment, whether
# the protected path is the argument of a reading command. The write guard did
# not. A write anywhere on the line plus a protected path anywhere else on the
# line added up to a refusal:
#
#     ls -ld /etc/systemd/system/ && rm -f /tmp/old.log
#
# deletes in the scratch area. /etc is read. It was refused anyway.
#
# Measured against a real audit log of 1066 write-guard refusals: 11 have this
# shape, spread over 11 DIFFERENT sessions — no single test run inflating the
# number. Replaying every distinct refused command through both versions: 57 run
# free afterwards, 0 become newly blocked.
#
# THIS LOOSENS A GUARD, so the first half of this file is the important one.
# Three shapes must survive, and each of them was a real hole during the work:
#
#   1. `cd <protected> && echo x > file` — the path is in the cd segment, the
#      target is a bare filename. Relative-target resolution ignores bare words
#      on purpose (otherwise every subcommand looks like a target), so cd
#      segments have to stay in the checked text.
#   2. `TARGET=/bin/sh; touch $TARGET` — the path lives in an assignment. The
#      value gets substituted into the writing segment; the assignment itself is
#      NOT added to the checked text, or an interpreter path in an assignment
#      would be a false positive next to any unrelated write.
#   3. `touch \<newline> /bin/x` — a line continuation. A shell joins it BEFORE
#      splitting anything, so it must be joined before segmenting too.
#
# Cases 2 and 3 were found by this suite AFTER the change looked finished
# locally. That is what the suite is for.
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
    "protected_reads": {"always_blocked_reads": [], "require_override_1": [],
                        "always_allowed": [], "env_files_require_override_1": []},
    "blocked_paths_write": ["/bin", "/etc", "/usr/bin", "~/.ssh", "/opt/inox"],
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
            input=json.dumps({"session_id": "write-segment-boundary-test",
                              "tool_name": "Bash",
                              "tool_input": {"command": command}}),
            capture_output=True, text=True, env=env)
    return p.returncode == 2, f"exit {p.returncode}: {' '.join(p.stderr.split())[:130]}"


def _stays_free(command: str) -> tuple[bool, str]:
    blocked, detail = _blocks(command)
    return not blocked, detail


# --- what must STAY refused. A miss here is a hole, not a false positive. ----

def check_write_in_the_second_segment_is_refused():
    return _blocks("ls -la /tmp && echo y > /etc/profile.d/x.sh")


def check_write_in_the_third_segment_is_refused():
    return _blocks("cd /tmp; ls -la; echo evil > /etc/profile.d/x.sh")


def check_copy_target_after_a_reading_segment_is_refused():
    return _blocks("ls -la /tmp && cp /tmp/x /etc/systemd/system/evil.service")


def check_cd_into_a_protected_dir_then_relative_write_is_refused():
    """The path is in the cd segment only; the target is a bare filename."""
    return _blocks("cd /etc && echo x > hosts")


def check_cd_in_one_segment_write_in_the_next_is_refused():
    return _blocks("cd /usr/bin; ls -la; echo x > python3")


def check_assignment_carries_the_path_is_refused():
    """The writing segment names the variable, not the path."""
    return _blocks("TARGET=/etc/passwd; touch $TARGET")


def check_braced_assignment_carries_the_path_is_refused():
    return _blocks("TARGET=/etc/passwd; touch ${TARGET}")


def check_target_behind_a_line_continuation_is_refused():
    """A shell joins the continuation before splitting; so must the guard."""
    return _blocks("touch \\\n  /etc/new")


def check_write_without_any_other_segment_is_refused():
    return _blocks("touch /etc/cron.d/evil")


def check_ssh_key_removal_stays_refused():
    return _blocks("cd /tmp && rm -rf ~/.ssh/id_rsa")


# --- what must run FREE. These are the measured false positives. ------------

def check_reading_etc_then_writing_elsewhere_stays_free():
    return _stays_free("ls -la /etc/hostname && rm -rf /tmp/mine")


def check_reading_etc_through_a_pipe_then_writing_stays_free():
    return _stays_free("cat /etc/passwd | grep root; touch /tmp/marker")


def check_listing_etc_then_cleaning_up_stays_free():
    return _stays_free("ls -ld /etc/systemd/system/ && rm -f /tmp/old.log")


def check_assignment_with_an_interpreter_path_stays_free():
    """An interpreter path in an assignment is not a target of an unrelated write."""
    return _stays_free("PY=/usr/bin/python3; $PY -c 'print(1)'; rm -f /tmp/old.log")


def check_reading_a_protected_file_multiline_then_writing_stays_free():
    return _stays_free("wc -l /etc/hostname\nmkdir -p /tmp/report")


def check_fetching_a_remote_config_stays_free():
    """Copying a protected path FROM a server into the scratch area reads it.

    Straight from the log: the remote path is the copy SOURCE, the local target
    is unprotected. The mkdir in the first segment used to make the whole line a
    write, which turned the remote path into a target.
    """
    return _stays_free(
        "mkdir -p /tmp/fetch && scp -q server:" + "/etc/hostname /tmp/fetch/")


CASES = [
    ("write in the second segment is refused", check_write_in_the_second_segment_is_refused),
    ("write in the third segment is refused", check_write_in_the_third_segment_is_refused),
    ("copy target after a reading segment is refused", check_copy_target_after_a_reading_segment_is_refused),
    ("cd into a protected dir then relative write is refused", check_cd_into_a_protected_dir_then_relative_write_is_refused),
    ("cd in one segment write in the next is refused", check_cd_in_one_segment_write_in_the_next_is_refused),
    ("assignment carries the path is refused", check_assignment_carries_the_path_is_refused),
    ("braced assignment carries the path is refused", check_braced_assignment_carries_the_path_is_refused),
    ("target behind a line continuation is refused", check_target_behind_a_line_continuation_is_refused),
    ("write without any other segment is refused", check_write_without_any_other_segment_is_refused),
    ("ssh key removal stays refused", check_ssh_key_removal_stays_refused),
    ("reading etc then writing elsewhere stays free", check_reading_etc_then_writing_elsewhere_stays_free),
    ("reading etc through a pipe then writing stays free", check_reading_etc_through_a_pipe_then_writing_stays_free),
    ("listing etc then cleaning up stays free", check_listing_etc_then_cleaning_up_stays_free),
    ("assignment with an interpreter path stays free", check_assignment_with_an_interpreter_path_stays_free),
    ("reading a protected file multiline then writing stays free", check_reading_a_protected_file_multiline_then_writing_stays_free),
    ("fetching a remote config stays free", check_fetching_a_remote_config_stays_free),
]

try:
    import pytest

    @pytest.mark.parametrize("name,fn", CASES)
    def test_write_guard_segment_boundary(name, fn):
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
