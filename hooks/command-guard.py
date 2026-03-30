#!/usr/bin/env python3
"""Command Guard Hook for Claude Code PreToolUse.

Checks Bash commands against security-rules.json before execution.
Exit 0 = allow, Exit 2 = block.

Part of: claude-code-safety-guard
License: MIT
"""

import json
import os
import re
import subprocess
import sys
from pathlib import Path

# Path to the security rules file
RULES_PATH = Path.home() / ".claude" / "safety-guard" / "security-rules.json"


def load_rules() -> dict:
    """Load security rules from JSON file."""
    if not RULES_PATH.exists():
        print(f"WARNING: {RULES_PATH} not found — no protection active", file=sys.stderr)
        return {}
    with open(RULES_PATH, encoding="utf-8") as f:
        return json.load(f)


def expand_path(path: str) -> str:
    """Expand ~ to $HOME."""
    return path.replace("~", str(Path.home()))


def check_blocked_patterns(command: str, patterns: list[str]) -> str | None:
    """Check if the command matches a blocked pattern."""
    for pattern in patterns:
        if ".*" in pattern:
            # Regex pattern
            if re.search(pattern, command):
                return pattern
        elif pattern in command:
            return pattern
    return None


def check_blocked_paths(command: str, paths: list[str]) -> str | None:
    """Check if the command writes to a protected path."""
    # Remove standard redirects (/dev/null is harmless)
    cleaned = re.sub(r'\d*>\s*/dev/null', '', command)
    cleaned = re.sub(r'\d*>&\d+', '', cleaned)

    # Detect write operations
    write_indicators = [
        ">", ">>", "tee ", "cp ", "mv ", "rm ", "touch ",
        "chmod ", "chown ", "mkdir ", "rmdir ", "ln ",
        "sed -i", "truncate ",
    ]
    is_write = any(indicator in cleaned for indicator in write_indicators)
    if not is_write:
        return None

    # Check both variants: original (~) and expanded (/home/user)
    cleaned_expanded = cleaned.replace("~", str(Path.home()))
    for path in paths:
        expanded = expand_path(path)
        if path in cleaned or expanded in cleaned or expanded in cleaned_expanded:
            return path
    return None


def load_override() -> dict | None:
    """Load active overrides from ~/.claude/.sudo-overrides/ directory.

    Each Claude Code instance creates its own override file:
    - With project: {name}.json (e.g. deploy-webapp.json)
    - Without project: system-{description}.json (e.g. system-maintenance.json)

    Format:
    {
        "override_level": 1,
        "label": "EXTENDED",
        "task": "Description of the task",
        "project": "my-project" or null,
        "confirmed": true,
        "timestamp": "ISO-8601",
        "expires_after": "task_completion"
    }

    The hook returns the override with the HIGHEST level.
    blocked_patterns remain ALWAYS active — even at Level 3.

    Backwards compatibility: Legacy .sudo-override.json is also read.
    """
    overrides_dir = Path.home() / ".claude" / ".sudo-overrides"
    active_overrides = []

    # New directory-based system
    if overrides_dir.is_dir():
        for filepath in overrides_dir.glob("*.json"):
            try:
                with open(filepath, encoding="utf-8") as f:
                    data = json.load(f)
                if data.get("confirmed") is True and data.get("task"):
                    data["_source_file"] = filepath.name
                    active_overrides.append(data)
            except (json.JSONDecodeError, KeyError):
                pass

    # Backwards compatibility: Legacy single file
    legacy_path = Path.home() / ".claude" / ".sudo-override.json"
    if legacy_path.exists():
        try:
            with open(legacy_path, encoding="utf-8") as f:
                data = json.load(f)
            if data.get("confirmed") is True and data.get("task"):
                data["_source_file"] = ".sudo-override.json (legacy)"
                active_overrides.append(data)
        except (json.JSONDecodeError, KeyError):
            pass

    if not active_overrides:
        return None

    # Return the highest override level
    return max(active_overrides, key=lambda o: o.get("override_level", 1))


def check_sudo(command: str, allowed: list[str]) -> str | None:
    """Check if sudo is only used with allowed commands."""
    if "sudo " not in command:
        return None

    # Load temporary overrides and merge with base allowlist
    override = load_override()
    override_commands = []
    if override:
        # New format: grants.additional_sudo
        grants = override.get("grants", {})
        additional = grants.get("additional_sudo", [])
        if additional == "all":
            return None  # Level 2+: All sudo allowed
        if isinstance(additional, list):
            override_commands = additional
        # Legacy format: commands
        override_commands += override.get("commands", [])
    all_allowed = allowed + override_commands

    # Extract the command after sudo (skip flags like -S, -E, -u)
    parts = command.split("sudo ")
    for part in parts[1:]:
        tokens = part.strip().split()
        # Skip sudo flags (start with -)
        cmd_after_sudo = ""
        for token in tokens:
            if token.startswith("-"):
                continue
            cmd_after_sudo = token
            break
        if cmd_after_sudo and cmd_after_sudo not in all_allowed:
            return cmd_after_sudo
    return None


def check_confirmation(command: str, patterns: list[str]) -> bool:
    """Check if the command requires confirmation (desktop notification)."""
    for pattern in patterns:
        if pattern in command:
            return True
    return False


def check_injection(command: str, keywords: list[str]) -> list[str]:
    """Check for prompt injection keywords."""
    found = []
    command_lower = command.lower()
    for keyword in keywords:
        if keyword.lower() in command_lower:
            found.append(keyword)
    return found


def main():
    """Main function — reads tool input from stdin, checks against rules."""
    try:
        input_data = json.load(sys.stdin)
    except (json.JSONDecodeError, EOFError):
        # Invalid input — allow through
        sys.exit(0)

    tool_name = input_data.get("tool_name", "")
    if tool_name != "Bash":
        sys.exit(0)

    tool_input = input_data.get("tool_input", {})
    command = tool_input.get("command", "")

    if not command:
        sys.exit(0)

    rules = load_rules()
    if not rules:
        sys.exit(0)

    # 1. Blocked patterns — ALWAYS active, even with override
    blocked = check_blocked_patterns(command, rules.get("blocked_patterns", []))
    if blocked:
        print(f"BLOCKED: Dangerous pattern detected: {blocked}", file=sys.stderr)
        sys.exit(2)

    # Override check: If active, skip all further checks
    # blocked_patterns above remains as safety net (rm -rf /, mkfs, etc.)
    override = load_override()
    if override:
        level = override.get("override_level", 1)
        label = override.get("label", "LEGACY")
        source = override.get("_source_file", "?")
        print(
            f"OVERRIDE ACTIVE: Level {level} ({label}) — "
            f"Task \"{override.get('task', '?')}\" [{source}] — "
            f"Checks 2-5 skipped for: {command[:100]}",
            file=sys.stderr,
        )
        sys.exit(0)

    # 2. Protected paths
    blocked_path = check_blocked_paths(command, rules.get("blocked_paths_write", []))
    if blocked_path:
        print(f"BLOCKED: Write access to protected path: {blocked_path}", file=sys.stderr)
        sys.exit(2)

    # 3. Sudo check
    bad_sudo = check_sudo(command, rules.get("allowed_sudo", []))
    if bad_sudo:
        print(f"BLOCKED: sudo with disallowed command: {bad_sudo}", file=sys.stderr)
        sys.exit(2)

    # 4. Confirmation-required commands — desktop notification
    if check_confirmation(command, rules.get("require_confirmation", [])):
        try:
            subprocess.Popen(
                ["notify-send", "-u", "normal", "-t", "5000",
                 "Claude Code — Package Installation",
                 f"Command being executed:\n{command[:200]}"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except FileNotFoundError:
            pass  # notify-send not installed — no problem

    # 5. Prompt injection warning (no block, just warning)
    injections = check_injection(command, rules.get("prompt_injection_keywords", []))
    if injections:
        print(
            f"WARNING: Possible prompt injection detected: {', '.join(injections)}",
            file=sys.stderr,
        )

    # All checks passed — allow through
    sys.exit(0)


if __name__ == "__main__":
    main()
