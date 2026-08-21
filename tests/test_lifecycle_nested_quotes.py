# ============================================================================
# The container lifecycle gate holds through nested quotes.
#
# This file adds no behaviour. It pins down a property the guard already has,
# because that property rests on something easy to "clean up" later.
#
# The suspicion that led here: `_PASSTHROUGH_RE` extracts the quoted section
# behind a pass-through and breaks on nesting — `sh -c 'printf "x" && docker rm
# -f c'` yields only `printf `. Since that same regex feeds check_lifecycle,
# which is a real GATE and not a notification, the question was whether a
# lifecycle subcommand can ride through inside nested quotes.
#
# Measured: it cannot. The gate also walks the SEGMENTS of the whole line, and
# the segment split ignores quotes — so the container command ends up at a
# command position anyway and is caught. The protection is real, but it rests on
# the coarseness of the segment split rather than on the extraction. Anyone
# making the split quote-aware would silently open this, and no test would have
# noticed. Now one does.
#
# One shape does stay free:
#     ssh server 'echo "a" && printf "b" docker rm -f c'
# There `docker rm` follows `printf` without a separator. That is not a bypass:
# on the far side `printf` would receive those words as arguments and nothing
# would be removed. Recorded here so the next reader does not re-investigate it.
#
# Note for whoever extends this: `run` and `exec` are deliberately in the FREE
# list. A first version of the probe used `docker run` as its control, saw
# everything pass, and measured nothing at all.
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
        env["CLAUDE_HOOK_DEV_FLAG"] = str(tmp / "_no_window")
        env["CLAUDE_GUARD_CONFIG"] = str(tmp / "_no_config.json")
        p = subprocess.run(
            ["python3", str(HOOK)],
            input=json.dumps({"session_id": "lifecycle-nested-quotes-test",
                              "tool_name": "Bash",
                              "tool_input": {"command": command}}),
            capture_output=True, text=True, env=env)
    return p.returncode == 2, f"exit {p.returncode}: {' '.join(p.stderr.split())[:150]}"


def _stays_free(command: str) -> tuple[bool, str]:
    blocked, detail = _blocks(command)
    return not blocked, detail


# --- the control: without it the whole file measures nothing ----------------

def check_plain_removal_is_gated():
    """If this ever goes green-as-free, every other case below is meaningless."""
    return _blocks("docker rm -f container")


# --- and it survives every layer of quoting ---------------------------------

def check_removal_behind_ssh_single_quotes():
    return _blocks("ssh server 'docker rm -f container'")


def check_removal_behind_ssh_double_quotes():
    return _blocks('ssh server "docker rm -f container"')


def check_removal_after_nested_quotes_and_chain():
    """Extraction yields only `printf ` here — the segment split catches it."""
    return _blocks("ssh server 'printf \"start\" && docker rm -f container'")


def check_removal_after_nested_quotes_and_semicolon():
    return _blocks("ssh server 'printf \"start\"; docker rm -f container'")


def check_volume_creation_behind_sh_c():
    return _blocks("sh -c 'printf \"x\" && docker volume create data'")


def check_removal_through_two_layers():
    """ssh, then sh -c, with a quoted string inside that."""
    return _blocks("ssh server \"sh -c 'printf \\\"x\\\" && docker rm -f container'\"")


# --- the gate must not swallow the harmless side ----------------------------

def check_read_only_subcommand_stays_free():
    return _stays_free("docker ps -a")


def check_container_command_as_mere_text_stays_free():
    return _stays_free("echo 'docker rm -f container'")


CASES = [
    ("plain removal is gated", check_plain_removal_is_gated),
    ("removal behind ssh single quotes", check_removal_behind_ssh_single_quotes),
    ("removal behind ssh double quotes", check_removal_behind_ssh_double_quotes),
    ("removal after nested quotes and chain", check_removal_after_nested_quotes_and_chain),
    ("removal after nested quotes and semicolon", check_removal_after_nested_quotes_and_semicolon),
    ("volume creation behind sh -c", check_volume_creation_behind_sh_c),
    ("removal through two layers", check_removal_through_two_layers),
    ("read-only subcommand stays free", check_read_only_subcommand_stays_free),
    ("container command as text stays free", check_container_command_as_mere_text_stays_free),
]

try:
    import pytest

    @pytest.mark.parametrize("name,fn", CASES)
    def test_lifecycle_nested_quotes(name, fn):
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
