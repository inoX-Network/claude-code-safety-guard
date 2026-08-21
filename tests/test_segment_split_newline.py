# ============================================================================
# A newline separates commands. The segment split has to know that.
#
# The guard splits a command line into segments in six places. Three knew the
# newline, three did not — and the gap cut both ways.
#
# TOO LAX: _remote_copy_writes reads tokens[0] per segment to see whether this
# segment starts a transfer. Without splitting on the newline, that word came
# from the PREVIOUS line — `echo` instead of `scp` — and the check ran into
# nothing. A transfer onto a protected server path was refused after `;` and
# after `&&`, and ran FREE after a newline. That is the deploy path the function
# exists to cover, and it was not theoretical: the audit log held a real
# deployment that had walked straight through it, writing the production path
# without any approval.
#
# TOO STRICT: the same gap in both copy-source helpers made a copy SOURCE count
# as a write target as soon as any command preceded it on its own line. So
# `mkdir -p /tmp/x` followed by `cp <protected-file> /tmp/x/` was refused —
# reading a protected file in order to back it up looked like writing to it.
#
# Both directions are covered below, because fixing one and not the other is how
# this class of bug survives. The counter-cases matter as much as the holes.
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
REMOTE = "server:/opt/protected/service/file"
SELF = f"{HOME}/.claude/settings.json"

RULES = {
    "protected_reads": {
        "always_blocked_reads": ["/etc/shadow"],
        "require_override_1": ["~/.ssh/id_", "~/.aws/credentials"],
        "always_allowed": ["~/.ssh/*.pub"],
        "env_files_require_override_1": [".env"],
    },
    "blocked_paths_write": ["/etc", "~/.ssh", "/opt/protected"],
    "blocked_patterns": [], "blocked_git_ops": [],
    "protected_git_branches": [], "blocked_bash_patterns_force_push": [],
    "allowed_sudo": [], "owner_only_commands": [], "require_confirmation": [],
}


def _run(command):
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
            "session_id": "newline-tests",
        })
        p = subprocess.run([sys.executable, str(HOOK)], input=payload,
                           capture_output=True, text=True, env=env)
        return p.returncode


def _blocked(command, why):
    rc = _run(command)
    return rc == 2, f"{why}: expected block, got exit {rc} for: {command!r}"


def _free(command, why):
    rc = _run(command)
    return rc == 0, f"{why}: expected free, got exit {rc} for: {command!r}"


# --- too lax: the transfer must be seen after a newline --------------------

def check_scp_after_newline():
    return _blocked(f"echo start\nscp /tmp/a {REMOTE}",
                    "a newline starts a new command")


def check_rsync_after_newline():
    return _blocked(f"echo start\nrsync /tmp/a {REMOTE}",
                    "rsync counts the same way")


def check_scp_after_two_newlines():
    return _blocked(f"echo one\necho two\nscp /tmp/a {REMOTE}",
                    "more lines in front change nothing")


def check_scp_after_newline_and_indent():
    return _blocked(f"echo start\n  scp /tmp/a {REMOTE}",
                    "leading whitespace does not hide it")


# --- too strict: a copy source is not a write target ------------------------

def check_copy_source_after_newline_stays_free():
    return _free(f"mkdir -p /tmp/z\ncp {SELF} /tmp/z/backup",
                 "backing up a protected file reads it")


def check_copy_source_after_touch_stays_free():
    return _free(f"touch /tmp/x\ncp {SELF} /tmp/z/backup",
                 "any preceding command, same result")


def check_env_template_copy_after_newline_stays_free():
    return _free("mkdir -p /tmp/z\ncp /tmp/template.env.example /tmp/z/.env",
                 "a template is read; the .env comes into being")


# --- already tight, must stay tight ----------------------------------------

def check_scp_alone_still_blocked():
    return _blocked(f"scp /tmp/a {REMOTE}", "the plain form was never open")


def check_scp_after_semicolon_still_blocked():
    return _blocked(f"echo start; scp /tmp/a {REMOTE}", "semicolons already split")


def check_scp_after_and_still_blocked():
    return _blocked(f"echo start && scp /tmp/a {REMOTE}", "&& already splits")


def check_copy_onto_protected_still_blocked():
    return _blocked(f"cp /tmp/a {SELF}", "writing TO a protected file")


def check_direct_write_still_blocked():
    return _blocked("echo x > /etc/cron.d/evil", "unrelated, must not regress")


# --- harmless, must stay free ----------------------------------------------

def check_scp_from_remote_stays_free():
    return _free(f"scp {REMOTE} /tmp/a", "fetching is not writing")


def check_local_copy_stays_free():
    return _free("cp /tmp/a /tmp/b", "nothing protected involved")


def check_multiline_without_copy_stays_free():
    return _free("echo one\necho two\nls /tmp", "plain multi-line work")


CASES = [
    ("scp after a newline", check_scp_after_newline),
    ("rsync after a newline", check_rsync_after_newline),
    ("scp after two newlines", check_scp_after_two_newlines),
    ("scp after a newline and indent", check_scp_after_newline_and_indent),
    ("copy source after newline stays free", check_copy_source_after_newline_stays_free),
    ("copy source after touch stays free", check_copy_source_after_touch_stays_free),
    ("env template copy stays free", check_env_template_copy_after_newline_stays_free),
    ("scp alone still blocked", check_scp_alone_still_blocked),
    ("scp after semicolon still blocked", check_scp_after_semicolon_still_blocked),
    ("scp after && still blocked", check_scp_after_and_still_blocked),
    ("copy onto protected still blocked", check_copy_onto_protected_still_blocked),
    ("direct write still blocked", check_direct_write_still_blocked),
    ("scp from remote stays free", check_scp_from_remote_stays_free),
    ("local copy stays free", check_local_copy_stays_free),
    ("multi-line without copy stays free", check_multiline_without_copy_stays_free),
]

try:
    import pytest

    @pytest.mark.parametrize("name,fn", CASES)
    def test_segment_split_newline(name, fn):
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
