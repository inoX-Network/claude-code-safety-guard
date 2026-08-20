# ============================================================================
# What sits inside the quotes is code, not prose — twice over.
#
# Two holes, one root: a part of the command IS a command, but was read as text.
#
# 1. awk. The operator search runs against the line WITHOUT quoted sections, so
#    `awk 'BEGIN{print "x" > "/path"}'` lost its whole program and looked like a
#    read. Both write checks — protected paths AND self-protection — pass through
#    that one gate, so awk walked past every protected path there is. Every other
#    form (echo, perl, python, tee, dd) was refused at the same targets.
#
# 2. find -exec. `find` is deliberately absent from RECURSIVE_READ_CMDS: listing
#    a protected directory stays allowed. With `-exec` it stops being a listing —
#    every match is handed to a command. `find /etc -name shadow -exec cat {} \;`
#    ran free while `cat /etc/shadow` was refused: the detour was the weaker door.
#
# The counter-cases matter as much as the holes. Two false alarms were built and
# removed while fixing this, both taken from real logged commands:
#   - `awk '{print $2, "->", $1}'` — the `>` lives inside the text "->".
#   - `cd ~ && … ; find Projects -exec du …` — the find sits in a LATER segment;
#     checking the whole line coloured the home directory from somewhere else.
# Measured: of 708 real awk calls containing `>`, 688 are comparisons. A blunt
# fix here costs about nine false alarms a day, which is why the redirect is
# recognised by its TARGET (a string) and only outside a string literal.
# ============================================================================
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
HOOK = Path(os.environ.get("GUARD_HOOK") or (REPO / "hooks" / "command-guard.py"))

HOME = os.path.expanduser("~")

RULES = {
    "protected_reads": {
        "always_blocked_reads": ["/etc/shadow"],
        "require_override_1": ["~/.ssh/id_", "~/.aws/credentials"],
        "always_allowed": ["~/.ssh/*.pub"],
        "env_files_require_override_1": [".env"],
    },
    "blocked_paths_write": ["/etc", "~/.ssh"],
    "blocked_patterns": [], "blocked_git_ops": [],
    "protected_git_branches": [], "blocked_bash_patterns_force_push": [],
    "allowed_sudo": ["tar", "grep"], "owner_only_commands": [],
    "require_confirmation": [],
}


def _run(command):
    """Runs the hook on a Bash command. Returns the exit code (2 = blocked)."""
    with tempfile.TemporaryDirectory() as d:
        rules = Path(d) / "rules.json"
        rules.write_text(json.dumps(RULES), encoding="utf-8")
        env = dict(os.environ)
        env["CLAUDE_SECURITY_RULES"] = str(rules)
        env["CLAUDE_SUDO_OVERRIDES_DIR"] = str(Path(d) / "no-overrides")
        env["CLAUDE_AUDIT_DIR"] = str(Path(d) / "audit")
        env["CLAUDE_HOOK_DEV_FLAG"] = str(Path(d) / "no-dev-mode")
        payload = json.dumps({
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "cwd": HOME,
            "session_id": "awk-tests",
        })
        p = subprocess.run([sys.executable, str(HOOK)], input=payload,
                           capture_output=True, text=True, env=env)
        return p.returncode


def _blocked(command, why):
    rc = _run(command)
    return rc == 2, f"{why}: expected block, got exit {rc} for: {command}"


def _free(command, why):
    rc = _run(command)
    return rc == 0, f"{why}: expected free, got exit {rc} for: {command}"


# --- the holes ------------------------------------------------------------

def check_awk_writes_hook_source():
    return _blocked(
        f"awk 'BEGIN{{print \"x\" > \"{HOME}/.claude/hooks/command-guard.py\"}}' /dev/null",
        "awk into the hook source")


def check_awk_writes_settings():
    return _blocked(
        f"awk 'BEGIN{{print \"x\" > \"{HOME}/.claude/settings.json\"}}' /dev/null",
        "awk into settings.json")


def check_awk_writes_override_dir():
    return _blocked(
        f"awk 'BEGIN{{print \"x\" > \"{HOME}/.claude/.sudo-overrides/forged.json\"}}' /dev/null",
        "awk into the override directory")


def check_awk_writes_etc():
    return _blocked("awk 'BEGIN{print \"x\" > \"/etc/cron.d/evil\"}' /dev/null",
                    "awk into /etc")


def check_awk_appends_etc():
    return _blocked("awk 'BEGIN{print \"x\" >> \"/etc/cron.d/evil\"}' /dev/null",
                    "awk appending to /etc")


def check_gawk_writes_etc():
    return _blocked("gawk 'BEGIN{print \"x\" > \"/etc/cron.d/evil\"}' /dev/null",
                    "gawk counts too")


def check_awk_printf_writes():
    return _blocked("awk 'BEGIN{printf \"x\" > \"/etc/passwd\"}' /dev/null",
                    "printf redirects as well")


def check_awk_with_v_flag():
    return _blocked("awk -v x=1 'BEGIN{print x > \"/etc/cron.d/evil\"}' /dev/null",
                    "a flag in front does not hide it")


def check_find_exec_reads_shadow():
    return _blocked(r"find /etc -name shadow -exec cat {} \;",
                    "find -exec over /etc")


def check_find_exec_plus_form():
    return _blocked(r"find /etc -name shadow -exec cat {} +",
                    "the + form executes too")


def check_find_execdir_reads():
    return _blocked(r"find /etc -name shadow -execdir cat {} \;",
                    "-execdir executes too")


# --- counter-cases: these must stay free ----------------------------------

def check_awk_comparison_stays_free():
    return _free("awk '$1 > 5 {print $2}' /tmp/data.txt",
                 "a comparison is not a redirect")


def check_awk_line_range_stays_free():
    return _free("awk 'NR>=2730 && NR<=2790' /tmp/source.py",
                 "line ranges use >= all the time")


def check_awk_arrow_in_text_stays_free():
    return _free("grep -v '^#' /tmp/fstab | awk '{print $2, \"->\", $1}'",
                 "the > lives inside the string \"->\"")


def check_awk_string_comparison_stays_free():
    return _free("awk '$1 > \"abc\" {print}' /tmp/data.txt",
                 "string comparison against a free path")


def check_awk_writing_free_path_stays_free():
    return _free("awk 'BEGIN{print \"x\" > \"/tmp/harmless.txt\"}' /dev/null",
                 "writing is fine where the path is not protected")


def check_awk_in_pipe_stays_free():
    return _free("grep -c x /tmp/a | awk '{print $1}'",
                 "plain field extraction")


def check_find_without_exec_stays_free():
    return _free("find /etc -name '*.conf'",
                 "listing a protected directory stays allowed")


def check_find_exec_on_free_path_stays_free():
    return _free(r"find /tmp -name x -exec cat {} \;",
                 "find -exec is only a problem over protected paths")


def check_find_exec_in_later_segment_stays_free():
    return _free(
        r"cd ~ && du -sh * | head -5; find Projects -maxdepth 4 -name node_modules -prune -exec du -sh {} +",
        "the find searches Projects, not the home directory")


def check_awk_word_in_prose_stays_free():
    return _free("echo 'we use awk for the evaluation'",
                 "a word is not a deed")


# --- already tight, must stay tight ---------------------------------------

def check_echo_redirect_still_blocked():
    return _blocked("echo x > /etc/cron.d/evil", "the direct form was never open")


def check_tee_still_blocked():
    return _blocked("echo x | tee /etc/cron.d/evil", "tee was never open")


def check_direct_shadow_read_still_blocked():
    return _blocked("cat /etc/shadow", "the direct read was never open")


CASES = [
    ("awk writes the hook source", check_awk_writes_hook_source),
    ("awk writes settings.json", check_awk_writes_settings),
    ("awk writes the override directory", check_awk_writes_override_dir),
    ("awk writes into /etc", check_awk_writes_etc),
    ("awk appends into /etc", check_awk_appends_etc),
    ("gawk counts as awk", check_gawk_writes_etc),
    ("awk printf redirects", check_awk_printf_writes),
    ("a -v flag does not hide the redirect", check_awk_with_v_flag),
    ("find -exec reads a protected file", check_find_exec_reads_shadow),
    ("find -exec in its + form", check_find_exec_plus_form),
    ("find -execdir reads too", check_find_execdir_reads),
    ("awk comparison stays free", check_awk_comparison_stays_free),
    ("awk line range stays free", check_awk_line_range_stays_free),
    ("awk arrow in text stays free", check_awk_arrow_in_text_stays_free),
    ("awk string comparison stays free", check_awk_string_comparison_stays_free),
    ("awk writing a free path stays free", check_awk_writing_free_path_stays_free),
    ("awk in a pipe stays free", check_awk_in_pipe_stays_free),
    ("find without -exec stays free", check_find_without_exec_stays_free),
    ("find -exec on a free path stays free", check_find_exec_on_free_path_stays_free),
    ("find -exec in a later segment stays free", check_find_exec_in_later_segment_stays_free),
    ("the word awk in prose stays free", check_awk_word_in_prose_stays_free),
    ("echo redirect still blocked", check_echo_redirect_still_blocked),
    ("tee still blocked", check_tee_still_blocked),
    ("direct shadow read still blocked", check_direct_shadow_read_still_blocked),
]

try:
    import pytest

    @pytest.mark.parametrize("name,fn", CASES)
    def test_awk_redirect_and_find_exec(name, fn):
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
