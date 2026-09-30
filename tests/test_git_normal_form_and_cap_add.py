# ============================================================================
# Git safety and the container capability check read ONE spelling each.
#
# Measured 2026-09-30 against release 2026.09.30 with the example rules. These
# ran through without any approval, although their category is "always
# blocked":
#
#   git -C <path> reset --hard          global options before the subcommand
#   git -C <path> push --force          (the patterns want 'git' right before
#   git -c k=v commit --amend            the subcommand)
#   git -C <path> commit --no-verify
#   git -C <path> config user.name x
#   git push origin main --force        git takes options AFTER the refspec
#   git add ./   git add -- .   git add :/   git add -v -A
#   docker run --cap-add=CAP_SYS_ADMIN  prefix, blank, quotes, comma list
#
# The fix leaves the rules file alone: before matching, the command is also
# brought into a normal form -- global options removed, 'git push' flags in
# front, 'git add' on the whole tree written as 'git add .' / 'git add -A'.
# Both the raw text and the normal form are matched, so no pattern that hit
# before can miss now. Capabilities are matched as a value, not a substring.
#
# The working directory is a throwaway directory, not a repository: the
# commit-on-main check asks git for the branch and must not colour the result.
# Pure dry run: only decisions are inspected.
# ============================================================================
import json
import os
import subprocess
import tempfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
HOOK = Path(os.environ.get("GUARD_HOOK") or (REPO / "hooks" / "command-guard.py"))
EXAMPLE_RULES = REPO / "security-rules.example.json"

# (id, command, must block)
CASES = [
    # --- git: staging the whole working tree ------------------------------
    ("git add . (the one spelling that held)", "git add .", True),
    ("git add -A (held)", "git add -A", True),
    ("git add ./", "git add ./", True),
    ("git add .//", "git add .//", True),
    ("git add -- .", "git add -- .", True),
    ("git add -v .", "git add -v .", True),
    ("git add :/", "git add :/", True),
    ("git add -v -A", "git add -v -A", True),
    # --- git: global options before the subcommand ------------------------
    ("git -C add .", "git -C /tmp/repo add .", True),
    ("git -C add -A", "git -C /tmp/repo add -A", True),
    ("git -C reset --hard", "git -C /tmp/repo reset --hard", True),
    ("git -C push --force", "git -C /tmp/repo push --force", True),
    ("git -c commit --amend", "git -c user.name=x commit --amend -m x", True),
    ("git -C commit --no-verify", "git -C /tmp/repo commit --no-verify -m x", True),
    ("git -C config writes", "git -C /tmp/repo config user.name x", True),
    ("git -C config --global writes", "git -C /tmp/repo config --global user.name x", True),
    ("git -C config --unset", "git -C /tmp/repo config --unset user.name", True),
    ("git -C quoted path", "git -C '/tmp/with blank' reset --hard", True),
    ("git --no-pager reset --hard", "git --no-pager reset --hard", True),
    ("git -C add ./ in a later segment", "cd /tmp && git -C repo add ./", True),
    # --- git: flags after the refspec -------------------------------------
    ("git -C push origin --force main", "git -C /tmp/repo push origin --force main", True),
    # With '=value' the blocked_git_ops pattern does not fire (it wants a blank
    # or the end after the flag) -- only the force-push rule carries this one,
    # and it must see the normal form too.
    ("git -C push --force-with-lease=value",
     "git -C /tmp/repo push --force-with-lease=main:abc origin main", True),
    ("push --force after main", "git push origin main --force", True),
    ("push -f after a branch", "git push origin feature/x -f", True),
    # --- git: stays free --------------------------------------------------
    ("git add a file", "git add README.md", False),
    ("git add ./file", "git add ./src/app.py", False),
    ("git add .gitignore", "git add .gitignore", False),
    ("git add -u", "git add -u", False),
    ("git -C add a file", "git -C /tmp/repo add README.md", False),
    ("git -C status", "git -C /tmp/repo status", False),
    ("git -C config read", "git -C /tmp/repo config --get user.name", False),
    # From the audit-log replay: ONE argument is a read, only a value behind
    # it writes. Without these the normal form would have cost 4 real reads.
    ("git -C config reads a key", "git -C /tmp/repo config core.hooksPath", False),
    ("git -C config reads, 2>&1 behind",
     "git -C /tmp/repo config core.sparseCheckout 2>&1; echo x", False),
    ("git -C push", "git -C /tmp/repo push origin feature/x", False),
    ("git --no-pager log", "git --no-pager log --oneline -3", False),
    ("git -C log -p", "git -C /tmp/repo log -p -1", False),
    # --- containers: dangerous capabilities -------------------------------
    ("cap-add=SYS_ADMIN (held)", "docker run --cap-add=SYS_ADMIN alpine", True),
    ("cap-add=CAP_SYS_ADMIN", "docker run --cap-add=CAP_SYS_ADMIN alpine", True),
    ("cap-add CAP_SYS_ADMIN", "docker run --cap-add CAP_SYS_ADMIN alpine", True),
    ("cap-add two blanks", "docker run --cap-add  SYS_ADMIN alpine", True),
    ("cap-add quoted", "docker run --cap-add='SYS_ADMIN' alpine", True),
    ("cap-add=cap_all", "docker run --cap-add=cap_all alpine", True),
    ("podman cap-add=CAP_SYS_ADMIN", "podman run --cap-add=CAP_SYS_ADMIN alpine", True),
    ("cap-add comma list", "docker run --cap-add=NET_ADMIN,SYS_ADMIN alpine", True),
    # --- containers: stays free -------------------------------------------
    ("cap-add=NET_ADMIN", "docker run --cap-add=NET_ADMIN alpine", False),
    ("cap-add CAP_NET_BIND_SERVICE", "docker run --cap-add CAP_NET_BIND_SERVICE alpine", False),
    ("cap-drop=ALL", "docker run --cap-drop=ALL alpine", False),
]


def _decide(command: str) -> int:
    with tempfile.TemporaryDirectory() as tmp:
        env = dict(os.environ)
        env["CLAUDE_SECURITY_RULES"] = str(EXAMPLE_RULES)
        env["CLAUDE_SUDO_OVERRIDES_DIR"] = tmp
        env["CLAUDE_AUDIT_DIR"] = tmp + "/audit"
        env["CLAUDE_HOOK_DEV_FLAG"] = tmp + "/_none"
        payload = {"tool_name": "Bash", "tool_input": {"command": command},
                   "cwd": tmp, "session_id": "git-normal-form-test",
                   "hook_event_name": "PreToolUse"}
        p = subprocess.run(["python3", str(HOOK)], input=json.dumps(payload),
                           capture_output=True, text=True, env=env, cwd=tmp)
        return p.returncode


@pytest.mark.parametrize("name,command,blocks", CASES, ids=[c[0] for c in CASES])
def test_git_normal_form_and_cap_add(name, command, blocks):
    blocked = _decide(command) != 0
    assert blocked == blocks, (
        f"{name!r}: expected {'block' if blocks else 'allow'}, "
        f"got {'block' if blocked else 'allow'}")
