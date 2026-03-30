# Claude Code Safety Guard — 3-Level Override System

[![Born from a real incident](https://img.shields.io/badge/born%20from-a%20real%20incident-red)](https://github.com/anthropics/claude-code/issues/39283)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A **PreToolUse hook system** that prevents destructive system operations in Claude Code, with a **3-level override mechanism** for when you actually need elevated permissions.

> **Context:** This project was born after [a real incident](https://github.com/anthropics/claude-code/issues/39283) where Claude Code executed a destructive `chown -R` on `/etc/` — requiring a 5-hour recovery session. The built-in permission system wasn't enough. This hook adds defense-in-depth.

## Features

- **Blocked patterns** — `rm -rf /`, `mkfs`, `chmod 777`, fork bombs, pipe-to-shell, recursive chown/chmod on system paths. These are **always** blocked, even with an active override.
- **Protected paths** — No write operations to `~/.ssh`, `/etc/shadow`, `/boot`, `/usr/bin`, etc. unless an override is active.
- **Sudo whitelist** — Only pre-approved commands can follow `sudo`. Everything else is blocked.
- **3-level override system** — Because sometimes you *need* elevated permissions. Scoped, explicit, and auditable.
- **Per-instance override files** — Multiple Claude Code sessions can run in parallel, each with their own scoped override.
- **Desktop notifications** — Get notified when packages are being installed (`pip install`, `npm install`, `apt install`, etc.).
- **Prompt injection detection** — Warns when suspicious keywords appear in commands (doesn't block, but logs to stderr).

## How It Works

```
User prompt → Claude Code → PreToolUse Hook → command-guard.py
                                                    │
                                          ┌─────────┼─────────┐
                                          ▼         ▼         ▼
                                    Blocked     Override   Normal
                                    Pattern?    Active?    Checks
                                      │           │         │
                                    EXIT 2      EXIT 0    Path/Sudo/
                                   (block)     (allow)    Injection
```

1. **Blocked patterns** are checked first — always, regardless of overrides
2. If an **override** is active, remaining checks are skipped (the operator explicitly granted permissions)
3. Otherwise: **protected paths**, **sudo whitelist**, **notifications**, and **injection detection** run in sequence

## Installation

### 1. Copy the files

```bash
# Create the directory structure
mkdir -p ~/.claude/hooks
mkdir -p ~/.claude/safety-guard
mkdir -p ~/.claude/rules

# Copy the hook
cp hooks/command-guard.py ~/.claude/hooks/command-guard.py

# Copy and customize the rules
cp security-rules.example.json ~/.claude/safety-guard/security-rules.json

# Copy the rules document (Claude reads this as context)
cp rules/security-operations.md ~/.claude/rules/security-operations.md
```

### 2. Configure the hook in settings.json

Add the hook to your Claude Code settings (`~/.claude/settings.json`):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "python3 ~/.claude/hooks/command-guard.py"
          }
        ]
      }
    ]
  }
}
```

See [settings.example.json](settings.example.json) for the complete example.

### 3. Customize the rules

Edit `~/.claude/safety-guard/security-rules.json` to match your system:

- **`allowed_sudo`** — Which commands are allowed after `sudo`. The example includes `apt`, `docker`, `systemctl`. Add or remove based on your workflow.
- **`blocked_paths_write`** — Paths that are protected from write operations. Add project-specific paths if needed.
- **`require_confirmation`** — Package managers that trigger desktop notifications.

## The Override System

The key insight: a static blocklist isn't enough. Sometimes you legitimately need `chown -R` (disaster recovery) or unrestricted `sudo` (system maintenance). Instead of disabling the guard entirely, the override system provides **scoped, explicit, auditable** elevated permissions.

### Level 1: EXTENDED

**For:** Deployments, container management, single-file config changes

```
Operator: "Level 1 granted for deploying the web app."
```

Unlocks: Additional sudo commands (e.g. `docker`, `docker compose`), single-file ops on protected paths.
Still blocked: Recursive operations on protected paths, system path modifications.

### Level 2: FULL

**For:** System maintenance, SSH config, firewall changes, SSL certificates

```
Operator: "Yes, Level 2 for SSH hardening."
```

Unlocks: All sudo commands, write access to all protected paths.
Still blocked: Recursive operations on system paths (`chown -R /etc/`), all blocked patterns.

### Level 3: CRITICAL

**For:** Emergencies only. Disaster recovery, OS upgrades.

```
Operator: "Level 3 confirmed. Snapshot ID: snap-abc123."
```

Prerequisites: System snapshot, documented snapshot ID, maximum runtime, double confirmation, no background agents.
Still blocked: All blocked patterns (`rm -rf /`, `mkfs`, `chmod 777`). **These can never be unlocked.**

### How Overrides Work

Override files are stored in `~/.claude/.sudo-overrides/`:

```json
{
  "override_level": 1,
  "label": "EXTENDED",
  "task": "Deploy web application v2.3",
  "project": "my-webapp",
  "confirmed": true,
  "timestamp": "2026-03-27T18:00:00Z",
  "expires_after": "task_completion",
  "grants": {
    "additional_sudo": ["docker", "docker compose"],
    "recursive_operations": false,
    "system_paths": false
  }
}
```

- Each Claude Code instance creates its **own** file
- Multiple sessions can run in parallel without conflicts
- The hook reads all override files and uses the **highest** level
- Overrides expire after task completion (the instance deletes its own file)

### Confirmation Rules

The operator **must** include the level number in their confirmation:

| Accepted | Not Accepted |
|----------|-------------|
| "Yes, Level 1" | "yes" |
| "Level 2 granted" | "ok, do it" |
| "you have Level 1" | "go ahead" |
| "1 is ok" | "sure" |

If the confirmation is unclear, Claude should ask: *"Which level? 1, 2, or 3?"*

## What's Always Blocked

These patterns cannot be unlocked by any override:

| Pattern | Why |
|---------|-----|
| `rm -rf /`, `rm -rf ~`, `rm -rf /*`, `rm -rf .` | Catastrophic data loss |
| `chmod 777`, `chmod -R 777` | Destroys file permissions |
| `mkfs`, `dd if=.* of=/dev/` | Formats/overwrites drives |
| `:(){ :\|:& };:` | Fork bomb |
| `curl ... \| sh`, `wget ... \| bash` | Arbitrary code execution |
| `eval.*base64` | Obfuscated code execution |
| `chown -R` / `chmod -R` / `chgrp -R` on system paths | The exact pattern from [the incident](https://github.com/anthropics/claude-code/issues/39283) |

## Configuration Reference

### security-rules.json

| Key | Type | Description |
|-----|------|-------------|
| `blocked_patterns` | `string[]` | Patterns that are always blocked (supports regex via `.*`) |
| `blocked_paths_write` | `string[]` | Paths protected from write operations (supports `~`) |
| `allowed_sudo` | `string[]` | Commands allowed after `sudo` |
| `require_confirmation` | `string[]` | Patterns that trigger desktop notifications |
| `prompt_injection_keywords` | `string[]` | Keywords that trigger warnings (not blocks) |

### Override file format

| Key | Type | Description |
|-----|------|-------------|
| `override_level` | `1 \| 2 \| 3` | Permission level |
| `label` | `string` | Human-readable label (EXTENDED/FULL/CRITICAL) |
| `task` | `string` | What the override is for |
| `project` | `string \| null` | Associated project (optional) |
| `confirmed` | `boolean` | Must be `true` |
| `timestamp` | `string` | ISO 8601 timestamp |
| `expires_after` | `string` | When the override expires |
| `grants.additional_sudo` | `string[] \| "all"` | Additional sudo commands (or "all" for Level 2+) |
| `grants.recursive_operations` | `boolean` | Whether recursive ops are allowed |
| `grants.system_paths` | `boolean` | Whether system path access is allowed |

## FAQ

**Q: Does this replace Claude Code's built-in permission system?**
A: No. This runs *alongside* it. Claude Code's permission prompts still appear. This hook adds an additional layer that catches dangerous patterns before they even reach the permission prompt.

**Q: What if I need to run a blocked pattern legitimately?**
A: The permanently blocked patterns (like `rm -rf /`) should never be run by an AI agent. For everything else, use the override system. If you need something that's not covered, edit your `security-rules.json`.

**Q: Does the prompt injection detection actually block anything?**
A: No — it only logs warnings to stderr. It's meant as a heads-up, not a hard block. Prompt injection via commands is an edge case, but it's worth monitoring.

**Q: Can I use this with multiple Claude Code sessions?**
A: Yes. Each session creates its own override file in `~/.claude/.sudo-overrides/`. They don't interfere with each other.

## Contributing

Issues and PRs welcome. If you've been bitten by a similar incident and have patterns to add to the blocklist, please share them.

## License

[MIT](LICENSE)

---

*Born from a real incident. Built to prevent the next one.*
