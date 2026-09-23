#!/usr/bin/env python3
"""What has to hold when the rules file lacks a SECTION.

`test_fallback_ruleset_completeness.py` covers the whole file going missing.
This covers the quieter case: an update adds sections to
security-rules.example.json, but never touches the user's rules file — it is
self-protected, and rightly so. An installation from an older release keeps
running on an older file.

Measured 2026-09-23: with one section missing, its protection was simply gone.
git reset --hard, the approval script, delete protection, credential reads and
MCP writes all ran free, while the same file with the section blocked them.
The owner chose a hard built-in default for these sections plus a notice, over
migrating the user's file.

Three things are pinned here:

  1. A missing critical section takes the built-in default (blocks again).
  2. An EXPLICIT entry, even an empty one, is kept — that is a decision, a
     missing key is an old file.
  3. The model is told once per session, on an allowed call, through the one
     documented PreToolUse channel that reaches anyone (additionalContext),
     without a permissionDecision — which would skip the permission prompt.
"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
HOOK = Path(os.environ.get("GUARD_HOOK") or (REPO / "hooks" / "command-guard.py"))
HOME = str(Path.home())
EXAMPLE = json.loads((REPO / "security-rules.example.json").read_text(encoding="utf-8"))


def _without(*keys):
    return {k: v for k, v in EXAMPLE.items() if k not in keys}


def _with(**changes):
    rules = dict(EXAMPLE)
    rules.update(changes)
    return rules


def _call(tool, tool_input, rules, *, shared=None, session="missing-sections",
          cwd=None):
    """Judge one call. rules=None means the rules file does not exist.

    Returns (exit code, parsed stdout JSON or None). `shared` is a directory
    kept across calls when a test needs the once-per-session memory; the rules
    file lives there too, because the notice names its path — a new path per
    call would be a new notice.
    """
    payload = {"tool_name": tool, "tool_input": tool_input, "session_id": session,
               "hook_event_name": "PreToolUse"}
    with tempfile.TemporaryDirectory() as own:
        tmp = shared or own
        path = Path(tmp) / "rules.json"
        if rules is not None:
            path.write_text(json.dumps(rules), encoding="utf-8")
        if cwd:
            payload["cwd"] = cwd
        env = dict(os.environ)
        env["CLAUDE_SECURITY_RULES"] = str(path)
        env["CLAUDE_SUDO_OVERRIDES_DIR"] = tmp
        env["CLAUDE_AUDIT_DIR"] = tmp
        env["CLAUDE_HOOK_DEV_FLAG"] = tmp + "/_none"
        # No configuration: English texts, whatever the machine running the
        # suite has set. A message check reads the wording.
        env["CLAUDE_GUARD_CONFIG"] = tmp + "/_no_config.json"
        r = subprocess.run([sys.executable, str(HOOK)], input=json.dumps(payload),
                           capture_output=True, text=True, env=env, timeout=60,
                           cwd=cwd or tmp)
        out = r.stdout.strip()
        return r.returncode, (json.loads(out) if out else None)


def _bash(command, rules, **kw):
    return _call("Bash", {"command": command}, rules, **kw)[0]


def _held(command, section):
    """Blocked with the full example AND with the section removed. Without the
    first half the case would not be about the section at all."""
    return (_bash(command, EXAMPLE) == 2
            and _bash(command, _without(section)) == 2)


MCP_WRITE = ("mcp__github__create_issue", {"title": "x"})


# --- 1. a missing critical section takes the built-in default ----------------

def check_blocked_patterns_default():
    return _held("chmod -R 777 /srv", "blocked_patterns")


def check_blocked_paths_write_default():
    return _held(f"echo x > {HOME}/.ssh/authorized_keys", "blocked_paths_write")


def check_protected_reads_default():
    return _held(f"cat {HOME}/.aws/credentials", "protected_reads")


def check_owner_only_commands_default():
    return _held("grant-override self --minutes 5", "owner_only_commands")


def check_blocked_git_ops_default():
    return _held("git reset --hard origin/main", "blocked_git_ops")


def check_blocked_paths_delete_default():
    return _held(f"rm -rf {HOME}/.claude/projects/p", "blocked_paths_delete")


def check_protected_git_branches_default():
    with tempfile.TemporaryDirectory() as repo:
        # A repository without a commit has no branch yet, and the guard
        # rightly finds nothing to protect there.
        subprocess.run(["git", "init", "-q", "-b", "main", repo], check=True)
        subprocess.run(["git", "-C", repo, "-c", "user.name=t", "-c",
                        "user.email=t@example.invalid", "commit", "-q",
                        "--allow-empty", "-m", "init"], check=True)
        cmd = "git commit -m change"
        return (_bash(cmd, EXAMPLE, cwd=repo) == 2
                and _bash(cmd, _without("protected_git_branches"), cwd=repo) == 2)


def check_mcp_policy_default():
    return (_call(*MCP_WRITE, EXAMPLE)[0] == 2
            and _call(*MCP_WRITE, _without("mcp_policy"))[0] == 2)


def check_mcp_write_blocked_without_rules_file():
    # The fallback said "fail-closed" and had no MCP part: every MCP write ran.
    return _call(*MCP_WRITE, None)[0] == 2


def check_mcp_read_stays_free_without_rules_file():
    return _call("mcp__github__get_issue", {"number": 1}, None)[0] == 0


def check_mcp_default_keeps_documentation_lookups_free():
    # The first default had no safe servers. On 3119 real allowed MCP calls,
    # 100 documentation lookups would have needed an override — stricter than
    # a fresh install from the example file, for no reason.
    call = ("mcp__context7__resolve-library-id", {"libraryName": "flask"})
    return (_call(*call, EXAMPLE)[0] == 0
            and _call(*call, _without("mcp_policy"))[0] == 0)


def check_mcp_default_gates_the_sensitive_server():
    call = ("mcp__postgres__query", {"sql": "select 1"})
    return (_call(*call, EXAMPLE)[0] == 2
            and _call(*call, _without("mcp_policy"))[0] == 2)


def check_ordinary_command_free_with_sections_missing():
    return _bash("ls -la /tmp", _without("blocked_git_ops", "mcp_policy")) == 0


# --- 2. an explicit entry is a decision and is kept --------------------------

def check_explicit_empty_git_ops_is_kept():
    return _bash("git reset --hard origin/main", _with(blocked_git_ops=[])) == 0


def check_explicit_empty_mcp_policy_is_kept():
    return _call(*MCP_WRITE, _with(mcp_policy={}))[0] == 0


# --- 3. the notice -----------------------------------------------------------

def _context(out):
    if not isinstance(out, dict):
        return None
    spec = out.get("hookSpecificOutput") or {}
    return spec.get("additionalContext")


def check_notice_names_the_missing_section():
    code, out = _call("Bash", {"command": "ls /tmp"}, _without("blocked_git_ops"))
    text = _context(out) or ""
    return code == 0 and "blocked_git_ops" in text and "built-in default" in text


def check_notice_sets_no_permission_decision():
    _, out = _call("Bash", {"command": "ls /tmp"}, _without("blocked_git_ops"))
    spec = (out or {}).get("hookSpecificOutput") or {}
    return (spec.get("hookEventName") == "PreToolUse"
            and "permissionDecision" not in spec and "decision" not in (out or {}))


def check_notice_names_an_unset_optional_section():
    code, out = _call("Bash", {"command": "ls /tmp"}, _without("docker"))
    text = _context(out) or ""
    return code == 0 and "docker" in text and "no built-in default" in text


def check_notice_when_rules_file_missing():
    code, out = _call("Bash", {"command": "ls /tmp"}, None)
    return code == 0 and "FALLBACK" in (_context(out) or "")


def check_no_notice_with_complete_rules():
    code, out = _call("Bash", {"command": "ls /tmp"}, EXAMPLE)
    return code == 0 and out is None


def check_notice_once_per_session():
    with tempfile.TemporaryDirectory() as shared:
        rules = _without("blocked_git_ops")
        first = _call("Bash", {"command": "ls /tmp"}, rules, shared=shared)[1]
        second = _call("Bash", {"command": "ls /"}, rules, shared=shared)[1]
        other = _call("Bash", {"command": "ls /"}, rules, shared=shared,
                      session="another-session")[1]
        return _context(first) and second is None and _context(other)


def check_no_notice_on_a_blocked_call():
    # stdout JSON next to exit 2 would be ignored at best; the notice waits for
    # the next allowed call of the session instead of being spent here.
    with tempfile.TemporaryDirectory() as shared:
        rules = _without("blocked_git_ops")
        blocked = _call("Bash", {"command": "git reset --hard"}, rules,
                        shared=shared)
        allowed = _call("Bash", {"command": "ls /tmp"}, rules, shared=shared)
        return blocked == (2, None) and bool(_context(allowed[1]))


CHECKS = [(name, fn) for name, fn in sorted(globals().items())
          if name.startswith("check_") and callable(fn)]


def test_missing_rule_sections():
    failed = [name for name, fn in CHECKS if not fn()]
    assert not failed, f"{len(failed)} of {len(CHECKS)} failed: {failed}"


if __name__ == "__main__":
    bad = [name for name, fn in CHECKS if not fn()]
    for name, _ in CHECKS:
        print(f"  {'FAIL' if name in bad else 'ok  '}  {name}")
    print(f"\n{len(CHECKS) - len(bad)} of {len(CHECKS)} passed")
    sys.exit(1 if bad else 0)
