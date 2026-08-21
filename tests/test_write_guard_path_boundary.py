# ============================================================================
# A protected write path must START where a path starts.
#
# The write guard compared by plain substring: `path in cleaned`. So the entry
# `/bin` matched every path that merely CONTAINS those characters —
# `~/Projekte/.../in-progress/bin`, `$BASE/bin/name`, `/tmp/sync/bin`. None of
# them writes to /bin. All of them were refused.
#
# Measured over 1063 real refusals in the log, cleaned of one test run that
# alone accounted for ~700 of them: 72 of the remaining refusals are this
# shape, spread over 49 different sessions. Roughly one per working day.
#
# THIS LOOSENS A GUARD. That is the whole risk, and it is why the second half of
# this file matters more than the first: every shape that SHOULD be refused has
# to stay refused. The self-protection gate already had a boundary — but only
# behind the path. What sits in FRONT of it was never checked, and that is
# exactly where `in-progress/bin` ends in `/bin`.
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
            input=json.dumps({"session_id": "write-path-boundary-test",
                              "tool_name": "Bash",
                              "tool_input": {"command": command}}),
            capture_output=True, text=True, env=env)
    return p.returncode == 2, f"exit {p.returncode}: {' '.join(p.stderr.split())[:130]}"


def _stays_free(command: str) -> tuple[bool, str]:
    blocked, detail = _blocks(command)
    return not blocked, detail


# --- the guard keeps doing its job. THIS HALF DECIDES. ----------------------

def check_writing_into_bin_is_refused():
    return _blocks("touch /bin/neu")


def check_redirect_into_bin_is_refused():
    return _blocks("echo x > /bin/sh")


def check_writing_into_etc_is_refused():
    return _blocks("cp /tmp/x /etc/passwd")


def check_writing_into_usr_bin_is_refused():
    return _blocks("mkdir /usr/bin/eigenes")


def check_writing_into_the_key_directory_is_refused():
    return _blocks("touch ~/.ssh/neu")


def check_writing_into_the_expanded_key_directory_is_refused():
    """Same directory, written out — the guard must not depend on the tilde."""
    return _blocks(f"touch {HOME}/.ssh/neu")


def check_writing_onto_the_server_path_is_refused():
    return _blocks("mkdir /opt/inox/dienst")


def check_traversal_into_bin_is_still_refused():
    """The traversal hardening must survive this change untouched."""
    return _blocks("touch /bin/../bin/neu")


def check_quoted_target_is_refused():
    return _blocks('echo x > "/bin/sh"')


def check_assignment_target_is_refused():
    """`ZIEL=/bin/sh` names the path just as much as a bare argument does."""
    return _blocks("ZIEL=/bin/sh; touch $ZIEL")


def check_write_after_a_harmless_segment_is_refused():
    return _blocks("cd /tmp && echo bereit; touch /etc/neu")


# --- the places a path can BEGIN. A missing one here is a way past. ---------
# These came from asking "where else can a path start", not from the log. The
# comma was genuinely missing on the first attempt: `{/tmp/a,/bin/b}` walked
# through. A too-narrow start list is a hole, so this list errs long.

def check_path_after_a_comma_is_refused():
    """The hole the first version had."""
    return _blocks("cp datei {/tmp/a,/bin/b}")


def check_path_in_brace_expansion_is_refused():
    return _blocks("mkdir -p {/bin/a,/tmp/b}")


def check_path_after_a_line_continuation_is_refused():
    return _blocks("touch \\\n  /bin/x")


def check_path_in_command_substitution_is_refused():
    return _blocks("echo $(touch /bin/x)")


def check_path_after_a_tab_is_refused():
    return _blocks("touch\t/bin/x")


def check_path_as_a_later_argument_is_refused():
    return _blocks("touch /tmp/a /bin/x")


def check_remote_destination_is_refused():
    """`host:/bin/x` — the colon introduces the path."""
    return _blocks("scp datei host:/opt/inox/x")


# --- and stops firing when the path is merely a TAIL of another one ---------

def check_project_directory_ending_in_bin_stays_free():
    """The measured shape: a project's own bin directory is not /bin."""
    return _stays_free(
        f"cd {HOME}/Projekte/inox-network-hub/security/in-progress/bin && rm -rf __pycache__")


def check_temp_directory_ending_in_bin_stays_free():
    return _stays_free("cd /tmp/safety-guard-sync/bin && rm ueberfluessiges")


def check_download_target_below_a_bin_segment_stays_free():
    return _stays_free('curl -s "https://example.invalid/bin/x" -o "skripte/x"')


def check_project_directory_ending_in_etc_stays_free():
    return _stays_free(f"touch {HOME}/projekt/etc/config.yaml")


def check_similar_name_stays_free():
    """`/binary` is not `/bin` — the boundary has to hold on both ends.

    Deliberately at the START of the path: an earlier version of this case used
    `/tmp/binary-datei`, where `/bin` never sits at a start position anyway. It
    was green with and without the trailing boundary and therefore proved
    nothing — a mutation removing that boundary survived it.
    """
    return _stays_free("touch /binary")


def check_longer_name_under_a_protected_root_stays_free():
    return _stays_free("touch /etcetera/datei")


def check_word_containing_bin_stays_free():
    return _stays_free("touch /tmp/kombinat/datei")


CASES = [
    ("writing into bin is refused", check_writing_into_bin_is_refused),
    ("redirect into bin is refused", check_redirect_into_bin_is_refused),
    ("writing into etc is refused", check_writing_into_etc_is_refused),
    ("writing into usr/bin is refused", check_writing_into_usr_bin_is_refused),
    ("writing into the key directory is refused", check_writing_into_the_key_directory_is_refused),
    ("expanded key directory is refused", check_writing_into_the_expanded_key_directory_is_refused),
    ("writing onto the server path is refused", check_writing_onto_the_server_path_is_refused),
    ("traversal into bin is still refused", check_traversal_into_bin_is_still_refused),
    ("quoted target is refused", check_quoted_target_is_refused),
    ("assignment target is refused", check_assignment_target_is_refused),
    ("write after a harmless segment is refused", check_write_after_a_harmless_segment_is_refused),
    ("path after a comma is refused", check_path_after_a_comma_is_refused),
    ("path in brace expansion is refused", check_path_in_brace_expansion_is_refused),
    ("path after a line continuation is refused", check_path_after_a_line_continuation_is_refused),
    ("path in command substitution is refused", check_path_in_command_substitution_is_refused),
    ("path after a tab is refused", check_path_after_a_tab_is_refused),
    ("path as a later argument is refused", check_path_as_a_later_argument_is_refused),
    ("remote destination is refused", check_remote_destination_is_refused),
    ("project directory ending in bin stays free", check_project_directory_ending_in_bin_stays_free),
    ("temp directory ending in bin stays free", check_temp_directory_ending_in_bin_stays_free),
    ("download below a bin segment stays free", check_download_target_below_a_bin_segment_stays_free),
    ("project directory ending in etc stays free", check_project_directory_ending_in_etc_stays_free),
    ("similar name stays free", check_similar_name_stays_free),
    ("longer name under a protected root stays free", check_longer_name_under_a_protected_root_stays_free),
    ("word containing bin stays free", check_word_containing_bin_stays_free),
]

try:
    import pytest

    @pytest.mark.parametrize("name,fn", CASES)
    def test_write_guard_path_boundary(name, fn):
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
