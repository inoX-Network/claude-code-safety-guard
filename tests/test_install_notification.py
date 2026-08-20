# ============================================================================
# The install notification must fire on a DEED, not on the word.
#
# It used to be a plain substring test over the whole line: as soon as one of
# the patterns (`pip install`, `pacman -S`, …) appeared anywhere in the text, a
# desktop popup went up — from a grep expression, a comment, a commit message,
# a docker volume name. A neighbouring session reported ~50 popups without a
# single installation.
#
# Measured over 86053 logged commands before touching anything:
#   455 notifications, of which 341 had the words merely inside another word.
#
# Two findings shaped the rule, and both came from the log rather than from
# reasoning:
#
#   1. A leading-command filter would have been WRONG. The 9 cases behind
#      `python -m pip install` are real, and `python` looks like a text command.
#      So the rule asks for consecutive TOKENS and not for the command position.
#
#   2. A plain token rule would have SILENCED 180 real installs sitting in
#      `docker exec … sh -c "pip install …"`. Container installs are the
#      majority of real ones here, so quotes behind a pass-through are opened
#      up rather than treated as a fence.
#
# Result: 455 → 422 notifications, 33 gone, none lost.
# ============================================================================
import json
import os
import subprocess
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
HOOK = Path(os.environ.get("GUARD_HOOK") or (REPO / "hooks" / "command-guard.py"))

PATTERNS = ["pip install", "pnpm add", "npm install", "pacman -S", "pacman -R",
            "cargo install", "go install"]

RULES = {
    "protected_reads": {"always_blocked_reads": [], "require_override_1": [],
                        "always_allowed": [], "env_files_require_override_1": []},
    "blocked_paths_write": [], "blocked_patterns": [], "blocked_git_ops": [],
    "protected_git_branches": [], "blocked_bash_patterns_force_push": [],
    # Empty on purpose: every case here runs without raised rights. An install
    # with root is refused at an earlier gate and would never reach step 5, so
    # such a case would measure that gate instead of the notification.
    "allowed_sudo": [], "owner_only_commands": [],
    "require_confirmation": PATTERNS,
}

# A notify-send stand-in that records its arguments, so the test can see what
# the guard actually asked for instead of trusting the source code.
RECORDER = (
    "#!/usr/bin/env python3\n"
    "import sys, os\n"
    "with open(os.environ['NOTIFY_LOG'], 'a', encoding='utf-8') as f:\n"
    "    f.write('\\x00'.join(sys.argv[1:]) + '\\n')\n"
)


def _run(command: str) -> tuple[bool, list[list[str]]]:
    """Runs the guard and returns (notified, recorded notify-send calls)."""
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        (tmp / "rules.json").write_text(json.dumps(RULES), encoding="utf-8")
        binn = tmp / "bin"
        binn.mkdir()
        recorder = binn / "notify-send"
        recorder.write_text(RECORDER, encoding="utf-8")
        recorder.chmod(0o755)
        log = tmp / "notify.log"

        env = dict(os.environ)
        env["CLAUDE_SECURITY_RULES"] = str(tmp / "rules.json")
        env["CLAUDE_SUDO_OVERRIDES_DIR"] = str(tmp / "ov")
        env["CLAUDE_AUDIT_DIR"] = str(tmp / "audit")
        env["CLAUDE_HOOK_DEV_FLAG"] = str(tmp / "_no_window")
        env["CLAUDE_GUARD_CONFIG"] = str(tmp / "_no_config.json")
        env["NOTIFY_LOG"] = str(log)
        env["PATH"] = str(binn) + os.pathsep + env["PATH"]

        subprocess.run(
            ["python3", str(HOOK)],
            input=json.dumps({"session_id": "install-notification-test",
                              "tool_name": "Bash",
                              "tool_input": {"command": command}}),
            capture_output=True, text=True, env=env)

        # The guard fires the notifier and exits without waiting for it.
        for _ in range(40):
            if log.exists() and log.read_text(encoding="utf-8").strip():
                break
            time.sleep(0.05)

        calls = []
        if log.exists():
            for line in log.read_text(encoding="utf-8").splitlines():
                if line:
                    calls.append(line.split("\x00"))
        return bool(calls), calls


def _notifies(command: str) -> tuple[bool, str]:
    fired, _ = _run(command)
    return fired, f"no notification for: {command}"


def _stays_quiet(command: str) -> tuple[bool, str]:
    fired, _ = _run(command)
    return not fired, f"unwanted notification for: {command}"


# --- a real install must still be announced ---------------------------------

def check_plain_install():
    return _notifies("pip install requests")


def check_install_behind_a_prefix():
    """A wrapper in front must not hide the install. Deliberately not `sudo`:
    an install with root fails at the sudo/lifecycle gate long before the
    notification, so that case would measure the wrong wall. `timeout N` is the
    shape the log actually holds."""
    return _notifies("timeout 90 pip install --quiet cryptography")


def check_bundled_short_flags():
    """`pacman -Syu` upgrades. Exact flag matching silenced this — measured,
    the old substring rule caught it by accident and the first token rule did
    not."""
    return _notifies("pacman -Syu --noconfirm")


def check_removal_with_bundled_flags():
    return _notifies("pacman -Rns python-foo")


def check_install_from_a_virtualenv():
    """Path in front, so the comparison has to run on the basename."""
    return _notifies("/tmp/venv/bin/pip install --quiet cryptography")


def check_install_via_module_switch():
    """The case a leading-command filter would have killed."""
    return _notifies("python3 -m pip install --quiet pip-audit")


def check_install_in_a_container():
    return _notifies('docker exec dev sh -c "pip install -q pip-audit"')


def check_install_in_a_container_with_nested_quotes():
    """The measured shape that extracting the quoted section fails on: pulling
    out the quotes yields only `printf `, and 13 real installs were missed."""
    return _notifies(
        'docker exec -w /tmp dev sh -c \'printf "PyJWT\\n" > /tmp/r.txt '
        '&& pip install --quiet pip-audit\'')


def check_install_over_ssh():
    return _notifies('ssh server "pacman -S --noconfirm htop"')


def check_install_in_a_later_segment():
    return _notifies("cd /tmp && ls -la; pip install requests")


def check_install_after_a_newline():
    return _notifies("cd /tmp\npip install requests")


# --- the word alone must stay quiet -----------------------------------------

def check_echo_about_installing():
    """20 logged cases of this shape — and the word sits inside `pnpm`."""
    return _stays_quiet('echo "FEHLT - pnpm install noetig"')


def check_grep_for_the_phrase():
    return _stays_quiet("grep -rn 'pip install' deploy/*.sh")


def check_docker_volume_named_after_pip():
    """48 logged cases: a cache volume is not an installation."""
    return _stays_quiet(
        "docker run --rm -v cockpit-pip-cache:/root/.cache/pip -w /app img true")


def check_pattern_list_in_a_script():
    """A measuring script that carries the patterns as DATA."""
    return _stays_quiet(
        'python3 -c "muster = [\'npm install\',\'pnpm add\',\'pip install\']"')


def check_filename_containing_the_words():
    return _stays_quiet("grep -c stripe projekte/bot/pnpm-lock.yaml")


def check_commit_message_mentioning_it():
    return _stays_quiet('git commit -m "pnpm install brach lokal ab"')


# --- the notification replaces itself instead of stacking -------------------

def check_notification_carries_a_replace_id():
    """Without a replace id every notice is a new popup. One measurement run
    produced 316 of them."""
    fired, calls = _run("pip install requests")
    if not fired:
        return False, "no notification at all"
    args = calls[0]
    if "-r" not in args:
        return False, f"no replace id in: {args}"
    value = args[args.index("-r") + 1]
    if not value.isdigit():
        return False, f"replace id is not a number: {value!r}"
    return True, ""


def check_repeated_notifications_share_the_id():
    _, first = _run("pip install requests")
    _, second = _run("pacman -S htop")
    if not first or not second:
        return False, "notification missing"
    a, b = first[0], second[0]
    id_a = a[a.index("-r") + 1] if "-r" in a else None
    id_b = b[b.index("-r") + 1] if "-r" in b else None
    if id_a != id_b:
        return False, f"ids differ: {id_a} vs {id_b}"
    return True, ""


CASES = [
    ("plain install notifies", check_plain_install),
    ("install behind a prefix notifies", check_install_behind_a_prefix),
    ("bundled short flags notify", check_bundled_short_flags),
    ("removal with bundled flags notifies", check_removal_with_bundled_flags),
    ("install from a virtualenv notifies", check_install_from_a_virtualenv),
    ("install via module switch notifies", check_install_via_module_switch),
    ("install in a container notifies", check_install_in_a_container),
    ("install with nested quotes notifies", check_install_in_a_container_with_nested_quotes),
    ("install over ssh notifies", check_install_over_ssh),
    ("install in a later segment notifies", check_install_in_a_later_segment),
    ("install after a newline notifies", check_install_after_a_newline),
    ("echo about installing stays quiet", check_echo_about_installing),
    ("grep for the phrase stays quiet", check_grep_for_the_phrase),
    ("pip cache volume stays quiet", check_docker_volume_named_after_pip),
    ("pattern list in a script stays quiet", check_pattern_list_in_a_script),
    ("filename with the words stays quiet", check_filename_containing_the_words),
    ("commit message stays quiet", check_commit_message_mentioning_it),
    ("notification carries a replace id", check_notification_carries_a_replace_id),
    ("repeated notifications share the id", check_repeated_notifications_share_the_id),
]

try:
    import pytest

    @pytest.mark.parametrize("name,fn", CASES)
    def test_install_notification(name, fn):
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
