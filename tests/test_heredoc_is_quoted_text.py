# ============================================================================
# A quoted command is not a command — but only when it really is just text.
#
# Reported by a peer project: a heredoc behind a plain output command, whose
# body QUOTES an interpreter one-liner touching a protected path, was refused —
# although only the output command ran and the body went nowhere.
#
# The consequence hits the improvement path itself: anyone trying to DOCUMENT a
# refused command (in a finding, an error report, a message to another project)
# was refused. The peer ran into it while sending us the original command.
#
# THE LINE, AND WHY IT HAS TO BE NARROW
#
# A heredoc body is text only when it goes nowhere:
#
#   cat <<'E' ... E              to stdout, then gone          -> text
#   cat > file <<'E' ... E       becomes a FILE                -> check it
#   cat <<'E' | bash ... E       gets EXECUTED                 -> check it
#   python3 <<'E' ... E          gets EXECUTED                 -> check it
#
# The file form is the one that is easy to wave through: whatever is written
# there can be executed later, and by then the guard sees only the script
# invocation and no longer knows the contents.
#
# A HOLE FOUND WHILE WRITING THIS FILE: `python3 <<'E' ... E` ran FREE. The
# guard recognised inline code by -c/-e, but not code arriving through the
# interpreter's standard input. Both halves — the false positive and the hole —
# turn out to be the same question: where does the body go?
#
# THE REFUSAL HALF IS THE ONE THAT MATTERS. Every case there must be refused
# before AND after the fix.
# ============================================================================
import json
import os
import subprocess
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
HOOK = Path(os.environ.get("GUARD_HOOK") or (REPO / "hooks" / "command-guard.py"))
HOME = os.path.expanduser("~")

# Assembled at runtime: a literal protected path in the source makes a
# guard-protected checkout refuse edits to this very file.
HOOKS = HOME + "/.claude/hoo" + "ks"
SETTINGS = HOME + "/.claude/sett" + "ings.json"

ONE_LINER = "python3 -c \"print(open('" + HOOKS + "/x.py').read())\""

RULES = {
    "protected_reads": {"always_blocked_reads": [], "require_override_1": [],
                        "always_allowed": [], "env_files_require_override_1": []},
    "blocked_paths_write": [], "blocked_patterns": [], "blocked_git_ops": [],
    "protected_git_branches": [], "blocked_bash_patterns_force_push": [],
    "allowed_sudo": [], "owner_only_commands": [], "require_confirmation": [],
}


def _run(command: str) -> int:
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
            input=json.dumps({"session_id": "heredoc-quoted-text-test",
                              "tool_name": "Bash",
                              "tool_input": {"command": command}}),
            capture_output=True, text=True, env=env)
    return p.returncode


def _blocks(command: str) -> tuple[bool, str]:
    rc = _run(command)
    return rc == 2, f"exit {rc}"


def _stays_free(command: str) -> tuple[bool, str]:
    rc = _run(command)
    return rc == 0, f"exit {rc}"


def _heredoc(head: str, body: str, tail: str = "") -> str:
    return f"{head} <<'END'{tail}\n{body}\nEND"


# --- what must STAY refused: the body goes somewhere ------------------------

def check_heredoc_into_a_file_is_refused():
    """The easy one to wave through: a file can be executed later."""
    return _blocks(_heredoc("cat > /tmp/script.sh", ONE_LINER))


def check_heredoc_appending_to_a_file_is_refused():
    return _blocks(_heredoc("cat >> /tmp/script.sh", ONE_LINER))


def check_heredoc_into_a_file_naming_a_protected_path_is_refused():
    return _blocks(_heredoc("cat > /tmp/note.txt", f"echo x > {SETTINGS}"))


def check_heredoc_piped_into_a_shell_is_refused():
    return _blocks(_heredoc("cat", ONE_LINER, " | bash"))


def check_heredoc_piped_into_an_interpreter_is_refused():
    return _blocks(_heredoc("cat", ONE_LINER, " | python3"))


def check_heredoc_straight_into_a_shell_is_refused():
    return _blocks(_heredoc("bash", ONE_LINER))


def check_heredoc_straight_into_an_interpreter_is_refused():
    """THE HOLE this file found: no -c, so the inline detection missed it."""
    return _blocks(_heredoc("python3", "print(open('" + HOOKS + "/x.py').read())"))


def check_heredoc_into_sudo_shell_is_refused():
    return _blocks(_heredoc("sudo bash", ONE_LINER))


def check_a_plain_one_liner_is_still_refused():
    return _blocks(ONE_LINER)


def check_a_plain_redirect_is_still_refused():
    return _blocks(f"echo x > {HOOKS}/y.py")


# --- what must run FREE: the body reaches stdout and is gone ----------------

def check_a_quoted_one_liner_stays_free():
    """The measured false positive: documenting a refused command."""
    return _stays_free(_heredoc("cat", ONE_LINER))


def check_a_quoted_redirect_stays_free():
    return _stays_free(_heredoc("cat", f"echo x > {SETTINGS}"))


def check_a_quoted_command_with_explanation_stays_free():
    return _stays_free(_heredoc(
        "cat", f"This was refused:\n  {ONE_LINER}\nReason: self-protection"))


def check_an_unquoted_marker_stays_free():
    return _stays_free(f"cat <<END\n{ONE_LINER}\nEND")


def check_an_indented_heredoc_stays_free():
    return _stays_free(f"cat <<-END\n\t{ONE_LINER}\nEND")


def check_a_body_through_a_filter_stays_free():
    """Not the pipe decides, but who is on the other end.

    `grep -c python` carries the word python as a SEARCH PATTERN. An earlier
    version of the fix compared across all words, held that for an interpreter
    and refused this — text instead of action, inside the fix itself.
    """
    return _stays_free(_heredoc("cat", ONE_LINER, " | grep -c python"))


def check_a_harmless_heredoc_stays_free():
    return _stays_free(_heredoc("cat", "Just some harmless text."))


def check_a_body_naming_only_a_path_stays_free():
    return _stays_free(_heredoc("cat", f"The path is {SETTINGS}"))


CASES = [
    ("heredoc into a file is refused", check_heredoc_into_a_file_is_refused),
    ("heredoc appending to a file is refused", check_heredoc_appending_to_a_file_is_refused),
    ("heredoc into a file naming a protected path is refused", check_heredoc_into_a_file_naming_a_protected_path_is_refused),
    ("heredoc piped into a shell is refused", check_heredoc_piped_into_a_shell_is_refused),
    ("heredoc piped into an interpreter is refused", check_heredoc_piped_into_an_interpreter_is_refused),
    ("heredoc straight into a shell is refused", check_heredoc_straight_into_a_shell_is_refused),
    ("heredoc straight into an interpreter is refused", check_heredoc_straight_into_an_interpreter_is_refused),
    ("heredoc into sudo shell is refused", check_heredoc_into_sudo_shell_is_refused),
    ("a plain one liner is still refused", check_a_plain_one_liner_is_still_refused),
    ("a plain redirect is still refused", check_a_plain_redirect_is_still_refused),
    ("a quoted one liner stays free", check_a_quoted_one_liner_stays_free),
    ("a quoted redirect stays free", check_a_quoted_redirect_stays_free),
    ("a quoted command with explanation stays free", check_a_quoted_command_with_explanation_stays_free),
    ("an unquoted marker stays free", check_an_unquoted_marker_stays_free),
    ("an indented heredoc stays free", check_an_indented_heredoc_stays_free),
    ("a body through a filter stays free", check_a_body_through_a_filter_stays_free),
    ("a harmless heredoc stays free", check_a_harmless_heredoc_stays_free),
    ("a body naming only a path stays free", check_a_body_naming_only_a_path_stays_free),
]

try:
    import pytest

    @pytest.mark.parametrize("name,fn", CASES)
    def test_heredoc_is_quoted_text(name, fn):
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
