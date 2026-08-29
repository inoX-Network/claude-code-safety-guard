#!/usr/bin/env python3
"""A level-1 grant covers what it names — not the zone the name sits in.

The gap this pins down (measured 2026-08-29, both editions): a grant on
`~/.ssh/config.d` passed the level check for the ENTRY `~/.ssh`, and with it
came authorized_keys, the private key and `rm -rf ~/.ssh`. The narrowing
introduced as H1 only ever worked downwards — a grant BELOW an entry silently
inherited the whole entry.

Why the existing suite never saw it: every grant test used
`allowed_paths=["/etc/fstab"]`, and /etc/fstab is itself an entry in
blocked_paths_write. Grant and entry are identical there, so the broken path is
never walked. One case with a grant below a DIRECTORY entry is enough.

The counter-direction matters just as much and is tested here too: the grant
must keep working for what it does name, and the H1 narrowing must survive
(a grant on '/etc' still does not cover '/etc/shadow').
"""
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
GUARD = str(Path(os.environ.get("GUARD_HOOK") or (REPO / "hooks" / "command-guard.py")))
HOME = str(Path.home())
SSH = f"{HOME}/.ssh"

RULES = {
    "blocked_paths_write": ["~/.ssh", "/etc", "/etc/shadow", "/opt/inox"],
    "blocked_paths_delete": ["~/.claude/projects"],
    "blocked_patterns": [],
    "allowed_sudo": [],
}


def _run(command, allowed_paths=None, level=1, tool="Bash"):
    """Judge one payload against a level-1 grant. Returns the exit code."""
    if tool == "Bash":
        payload = {"tool_name": "Bash", "tool_input": {"command": command}}
    else:
        payload = {"tool_name": tool,
                   "tool_input": {"file_path": command, "content": "x"}}
    payload.update({"session_id": "grant-below", "hook_event_name": "PreToolUse"})
    with tempfile.TemporaryDirectory() as tmp:
        rules_file = Path(tmp) / "rules.json"
        rules_file.write_text(json.dumps(RULES), encoding="utf-8")
        if allowed_paths is not None:
            expires = (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat()
            (Path(tmp) / "probe.json").write_text(json.dumps({
                "override_level": level, "task": "grant below a directory entry",
                "confirmed": True, "expires_at": expires,
                "grants": {"additional_sudo": [], "allowed_paths": allowed_paths},
            }), encoding="utf-8")
        env = dict(os.environ)
        env["CLAUDE_SECURITY_RULES"] = str(rules_file)
        env["CLAUDE_SUDO_OVERRIDES_DIR"] = tmp
        env["CLAUDE_AUDIT_DIR"] = tmp
        env["CLAUDE_HOOK_DEV_FLAG"] = tmp + "/_none"
        return subprocess.run([sys.executable, GUARD], input=json.dumps(payload),
                              capture_output=True, text=True, env=env,
                              timeout=60, cwd=tmp).returncode


def _blocks(command, allowed_paths=None, tool="Bash"):
    return _run(command, allowed_paths, tool=tool) == 2


def _stays_free(command, allowed_paths=None, tool="Bash"):
    return _run(command, allowed_paths, tool=tool) == 0


# --- what the grant MUST still allow ---------------------------------------

def check_grant_allows_its_own_directory():
    return _stays_free(f"echo x > {SSH}/config.d/work", [f"{SSH}/config.d"])


def check_grant_allows_its_own_directory_via_write_tool():
    return _stays_free(f"{SSH}/config.d/work", [f"{SSH}/config.d"], tool="Write")


def check_grant_on_the_entry_itself_still_works():
    return _stays_free(f"echo x > {SSH}/authorized_keys", [SSH])


def check_deep_grant_allows_deeper_file():
    return _stays_free(f"echo x > {SSH}/config.d/sub/deep", [f"{SSH}/config.d"])


def check_level_two_is_unaffected():
    return _run(f"echo x > {SSH}/authorized_keys", [], level=2) == 0


# --- what the grant must NOT drag along -------------------------------------

def check_neighbour_file_in_the_same_zone_stays_blocked():
    return _blocks(f"echo x > {SSH}/authorized_keys", [f"{SSH}/config.d"])


def check_neighbour_file_via_write_tool_stays_blocked():
    return _blocks(f"{SSH}/authorized_keys", [f"{SSH}/config.d"], tool="Write")


def check_private_key_stays_blocked():
    return _blocks(f"echo x > {SSH}/id_rsa", [f"{SSH}/config.d"])


def check_deleting_the_whole_zone_stays_blocked():
    return _blocks(f"rm -rf {SSH}", [f"{SSH}/config.d"])


def check_sibling_service_stays_blocked():
    return _blocks("echo x > /opt/inox/legal/app.py", ["/opt/inox/billing"])


def check_deleting_the_whole_service_tree_stays_blocked():
    return _blocks("rm -rf /opt/inox", ["/opt/inox/billing"])


def check_system_config_stays_blocked_with_a_subdirectory_grant():
    return _blocks("echo x > /etc/passwd", ["/etc/traefik"])


# --- the H1 narrowing must survive ------------------------------------------

def check_broad_grant_still_does_not_cover_a_deeper_entry():
    return _blocks("echo x > /etc/shadow", ["/etc"])


def check_grant_on_a_file_covers_only_that_file():
    return _blocks("echo x > /etc/shadow", ["/etc/passwd"])


# --- without a grant nothing changes ----------------------------------------

def check_no_grant_still_blocks():
    return _blocks(f"echo x > {SSH}/authorized_keys")


# --- targets the guard cannot resolve to a path -----------------------------
# check_blocked_paths expands before matching, so it finds the entry in
# "$HOME/.ssh/...". The target extraction has to expand too — otherwise the
# grant either loses cases it does cover, or (worse) waves through the ones it
# does not.

def check_neighbour_behind_a_variable_stays_blocked():
    return _blocks("echo x > $HOME/.ssh/authorized_keys", [f"{SSH}/config.d"])


def check_granted_directory_behind_a_variable_stays_free():
    return _stays_free("echo x > $HOME/.ssh/config.d/work", [f"{SSH}/config.d"])


def check_traversal_disguised_neighbour_stays_blocked():
    return _blocks(f"cp /tmp/x /tmp/..{HOME}/.ssh/authorized_keys",
                   [f"{SSH}/config.d"])


def check_traversal_inside_the_granted_directory_stays_free():
    return _stays_free("echo x > /opt/./inox/billing/app.py", ["/opt/inox/billing"])


def check_double_slash_inside_the_granted_directory_stays_free():
    return _stays_free("echo x > /opt//inox/billing/app.py", ["/opt/inox/billing"])


def check_target_hidden_in_a_variable_assignment_stays_blocked():
    # Nothing here resolves to a path — the fail-closed branch has to hold.
    return _blocks("ZIEL=$HOME/.ssh; echo x > $ZIEL/authorized_keys",
                   [f"{SSH}/config.d"])


def check_unprotected_neighbour_stays_free():
    return _stays_free(f"echo x > {HOME}/.ssh-backup/notes", [f"{SSH}/config.d"])


CHECKS = [(name, fn) for name, fn in sorted(globals().items())
          if name.startswith("check_") and callable(fn)]


def test_grant_below_a_directory_entry():
    failed = [name for name, fn in CHECKS if not fn()]
    assert not failed, f"{len(failed)} of {len(CHECKS)} failed: {failed}"


if __name__ == "__main__":
    bad = [name for name, fn in CHECKS if not fn()]
    for name, _ in CHECKS:
        print(f"  {'FAIL' if name in bad else 'ok  '}  {name}")
    print(f"\n{len(CHECKS) - len(bad)} of {len(CHECKS)} passed")
    sys.exit(1 if bad else 0)
