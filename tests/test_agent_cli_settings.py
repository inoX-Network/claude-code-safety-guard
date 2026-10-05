# ============================================================================
# The claude CLI writes its own settings and starts sessions without the hooks.
#
# The guard protects ~/.claude/settings.json by its path. The claude CLI writes
# that file itself, with no path on the command line: measured live on
# 2026-10-02, `claude plugin disable <name>` passed the guard and rewrote the
# settings file. Plugins bring their own hooks and MCP servers, so the same CLI
# can add code that runs next to the guard.
#
# The second way is worse. CLI 2.1.289 documents three start options that
# leave the user's hooks out -- and with them this guard:
#
#   --safe-mode       hooks, plugins, MCP off; Bash, login, permissions normal
#   --bare            hooks off; Bash and file edits on
#   --restricted      user settings ignored
#
# plus --setting-sources without `user`, a CLAUDE_CONFIG_DIR pointing
# elsewhere, and the environment variables the first two options set. A child
# session started that way runs without the guard.
#
# Measured before this fix, both language versions: 51 of 51 writing or
# hook-dropping calls passed, 34 of 34 reading or plain session starts passed.
#
# What stays free on purpose: starting sessions -- visible, in a chosen
# directory, with bypassPermissions and Remote Control -- and managing them
# (--bg, attach, respawn, logs, stop, rm). The owner reaches every session from
# a phone that way; blocking the start would block the work, not the risk.
#
# An unknown subcommand right after the program name counts as writing: a
# future `claude <something>` that edits settings must not pass because this
# list has not heard of it yet.
#
# The test reads the message, not just the exit code: several cases name
# protected paths and could be caught by a different rule. The language is
# pinned by an own config without a "language" key.
#
# Pure DRY-RUN: only the decision is inspected, nothing is executed.
# ============================================================================
import json
import os
import subprocess
import tempfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
HOOK = REPO / "hooks" / "command-guard.py"
EXAMPLE_RULES = REPO / "security-rules.example.json"

# Word stem of this rule's message, English and German.
MARKERS = ("agent cli", "agenten-cli")


def _blocked_by_cli_rule(command: str) -> bool:
    """True if the AGENT-CLI rule rejected the command."""
    with tempfile.TemporaryDirectory() as ov:
        cfg = os.path.join(ov, "guard-config.json")
        Path(cfg).write_text(json.dumps({"installation": {}}), encoding="utf-8")
        payload = {
            "session_id": "agent-cli-test",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": command},
        }
        env = dict(os.environ)
        env["CLAUDE_GUARD_CONFIG"] = cfg
        env["CLAUDE_SECURITY_RULES"] = str(EXAMPLE_RULES)
        env["CLAUDE_SUDO_OVERRIDES_DIR"] = ov
        env["CLAUDE_AUDIT_DIR"] = ov
        env["CLAUDE_HOOK_DEV_FLAG"] = ov + "/_none"
        p = subprocess.run(["python3", str(HOOK)], input=json.dumps(payload),
                           capture_output=True, text=True, env=env, timeout=60)
        return any(m in (p.stderr or "").lower() for m in MARKERS)


# --- writes settings, credentials or local state: owner only ----------------

WRITES = [
    "claude plugin disable foo@synced",
    "claude plugin enable foo@synced",
    "claude plugin install foo@market",
    "claude plugin i foo@market",
    "claude plugins install foo@market",
    "claude plugin uninstall foo",
    "claude plugin remove foo",
    "claude plugin update foo",
    "claude plugin prune",
    "claude plugin configure foo --values-stdin",
    "claude plugin init my-plugin",
    "claude plugin eval .",
    "claude plugin marketplace add https://example.invalid/market",
    "claude plugin marketplace remove market",
    "claude plugin marketplace update",
    "claude mcp add tool -- npx tool",
    "claude mcp add-json tool '{}'",
    "claude mcp add-from-claude-desktop",
    "claude mcp remove tool",
    "claude mcp reset-project-choices",
    "claude mcp login tool",
    "claude mcp logout tool",
    "claude mcp serve",
    "claude auth login",
    "claude auth logout",
    "claude auto-mode reset --yes",
    "claude import",
    "claude update",
    "claude upgrade",
    "claude install latest",
    "claude setup-token",
    "claude purge .",
    "claude gateway --config g.yaml",
    "claude ultrareview",
    "claude self-hosted-runner setup",
    "claude some-new-subcommand",
    "claude -p --debug-file /tmp/x 'hi'",
]

# --- starts a session without the user's hooks, or with changed settings ----

DROPS_HOOKS = [
    "claude --safe-mode -p 'hi'",
    "claude --bare -p 'hi'",
    "claude --restricted -p 'hi'",
    "claude -p --setting-sources project 'hi'",
    "claude -p --setting-sources=project 'hi'",
    "claude -p --settings '{\"disableAllHooks\": true}' 'hi'",
    "claude -p --plugin-dir /tmp/p 'hi'",
    "claude -p --plugin-url https://example.invalid/p.zip 'hi'",
    "claude -p --mcp-config /tmp/m.json 'hi'",
    "claude -p --agents '{}' 'hi'",
    "claude --channels plugin:x@y",
    "claude --dangerously-load-development-channels server:x",
    "claude --bg --exec 'pytest -x'",
    "claude agents --settings /tmp/s.json",
    "claude --dangerously-skip-permissions --safe-mode --remote-control x",
    "CLAUDE_CODE_SAFE_MODE=1 claude -p 'hi'",
    "CLAUDE_CODE_SIMPLE=1 claude -p 'hi'",
    "CLAUDE_CONFIG_DIR=/tmp/c claude -p 'hi'",
    "env CLAUDE_CODE_SAFE_MODE=1 claude -p 'hi'",
    "export CLAUDE_CODE_SAFE_MODE=1; claude -p 'hi'",
    "export CLAUDE_CONFIG_DIR=/tmp/c && claude",
]

# --- the same, hidden behind a wrapper, a path or a later segment -----------

HIDDEN = [
    "cd /tmp && claude --bg --safe-mode 'hi'",
    "timeout 60 claude --safe-mode -p 'hi'",
    "nohup claude --bare -p 'hi'",
    "sudo -u nobody claude plugin install x",
    "~/.local/bin/claude --safe-mode -p 'hi'",
    "/usr/bin/claude plugin disable x",
    "echo start; claude plugin install x",
    "ls /tmp | xargs claude --safe-mode -p",
    "bash -c 'claude --safe-mode -p hi'",
    "sh -c \"claude plugin install x\"",
    "claude -n doctor plugin install x",
]

# --- reads, or starts and manages ordinary sessions: free --------------------

FREE = [
    "claude --version",
    "claude -v",
    "claude --help",
    "claude plugin install --help",
    "claude doctor",
    "claude agents",
    "claude agents --json",
    "claude plugin list",
    "claude plugin details foo",
    "claude plugin validate .",
    "claude plugin marketplace list",
    "claude mcp list",
    "claude mcp get tool",
    "claude mcp",
    "claude auth status",
    "claude auto-mode config",
    "claude auto-mode defaults",
    "claude auto-mode critique",
    "claude logs abc123",
    "claude -p 'hi'",
    "claude -p 'install the update'",
    "claude --dangerously-skip-permissions --remote-control workshop",
    "claude --permission-mode bypassPermissions --remote-control",
    "claude --rc",
    "cd ~/project && claude --dangerously-skip-permissions --remote-control proj",
    "claude remote-control --name proj",
    "claude --bg 'hi'",
    "claude attach abc123",
    "claude respawn abc123",
    "claude respawn --all",
    "claude stop abc123",
    "claude kill abc123",
    "claude rm abc123",
    "claude daemon status",
    "claude daemon stop --any",
    "claude -n workshop --model opus --effort high",
    "claude -c",
    "claude --resume abc",
    "claude -w branch",
    "claude --add-dir /tmp -p 'hi'",
    "claude --agent builder -p 'hi'",
    "claude --strict-mcp-config -p 'hi'",
    "claude",
]

# --- the name as text, not as a call -----------------------------------------

TEXT = [
    "grep -n 'claude --safe-mode' notes.md",
    "echo 'claude plugin install' > /tmp/note.txt",
    "git commit -m 'explain claude --bare'",
    "cat ~/.claude/plugins/installed.json",
    "ls ~/.claude",
    "printf '%s\\n' CLAUDE_CODE_SAFE_MODE=1",
    "grep CLAUDE_CONFIG_DIR README.md",
]


@pytest.mark.parametrize("command", WRITES)
def test_writing_subcommand_is_owner_only(command):
    assert _blocked_by_cli_rule(command)


@pytest.mark.parametrize("command", DROPS_HOOKS)
def test_session_without_user_hooks_is_owner_only(command):
    assert _blocked_by_cli_rule(command)


@pytest.mark.parametrize("command", HIDDEN)
def test_hidden_call_is_found(command):
    assert _blocked_by_cli_rule(command)


@pytest.mark.parametrize("command", FREE)
def test_reading_and_session_management_stay_free(command):
    assert not _blocked_by_cli_rule(command)


@pytest.mark.parametrize("command", TEXT)
def test_name_as_text_is_no_call(command):
    assert not _blocked_by_cli_rule(command)
