# Security Rules for System Operations

This system is the operator's PRIMARY machine — not a container, not a sandbox.
Every mistake touches real data.

For bash commands:
- Check with `pwd` whether you are in the right directory
- Before deleting files: show `ls` first, then let the user confirm
- Before changing configs: create a backup (file.bak)
- NO curl/wget on unknown URLs without asking
- NO credentials in commands — use .env or SSH keys
- NO operations on ~/.ssh/, ~/.gnupg/, /etc/, /boot/

For WebSearch/URL fetching:
- NEVER put API keys or passwords in search queries
- NEVER call internal/localhost URLs
- When unsure: ask the operator before opening a URL

---

## The protection system is armed (command-guard.py)

The PreToolUse hook `command-guard.py` enforces these rules technically — for
**Bash, Read, Write, Edit, MultiEdit, NotebookEdit**. The rules below are therefore
not just convention; they are enforced by the hook. The **JSON override file + the
hook are the authority — not the prompt.** You cannot grant yourself any rights.

### Self-protection — paths the AI can NEVER write (no override lifts this)

`~/.claude/.sudo-overrides` (the active override directory), `~/.claude/bin`
(approval scripts), `~/.claude/hooks` (hook sources), `~/.claude/settings.json`,
`~/.claude/settings.local.json`, `~/.claude/CLAUDE.md`, `~/.claude/rules` (this
file!), `~/.claude/safety-guard/security-rules.json`, `~/.claude/.hook-dev-mode`.

Only the owner's `!` command (which bypasses the guard) or the hook dev mode
(see below, for hook sources only) can change these files.

### Owner-exclusive commands (`owner_only`)

The AI must NOT invoke the approval and dev-mode scripts via Bash (hard-blocked) —
otherwise it could grant itself permissions. Only the owner's `!` invocation
reaches these scripts.

---

## Override system: Security Pyramid v2

The owner can grant me elevated permissions for a specific task. The override
system has **three levels** with increasing rights and increasing risk.

### Level 1: EXTENDED (Deployment, Configuration)

**What is allowed:**
- Write access to explicitly approved paths (`grants.allowed_paths`, path-boundary-exact)
- Additional sudo commands (`grants.additional_sudo`, e.g. `docker`, `systemctl`)
- Individual file operations on normally protected paths

**What is NOT allowed:**
- Recursive operations (`-R`, `-r`, `--recursive`) on protected paths
- Operations on system paths (`/usr/`, `/lib/`, `/bin/`, `/sbin/`)
- `chown` or `chmod` on `/etc/` (only explicitly named files)

**Explanation requirement:** WHAT you are doing + WHY

**Typical tasks:** Deploy a container, change a reverse-proxy config, restart a service

### Level 2: FULL (System Maintenance, Security Fixes)

**What is additionally allowed:**
- Write access to ALL normally protected paths
- All sudo commands
- Individual file operations on system paths (`/etc/ssh/sshd_config`)

**What is NOT allowed:**
- Recursive operations on system paths — NEVER
- `chown -R`, `chmod -R`, `rm -r` on `/etc/`, `/usr/`, `/var/`, `/lib/`, `/bin/`, `/sbin/`, `/boot/`

**Approval friction:** Level 2 requires `--confirm FULL` when granting.
**Explanation requirement:** WHAT + WHY + RISK + concrete ROLLBACK command

**Typical tasks:** SSH configuration, firewall, SSL certificates, Fail2Ban

### Level 3: CRITICAL (Emergencies — maximum risk)

**What is additionally allowed:**
- Recursive operations on non-system paths that could reach system paths via bind mounts

**Mandatory preconditions:**
- A server snapshot MUST be created beforehand (hosting provider panel)
- The snapshot ID MUST be documented (`--snapshot <SNAPSHOT-ID>` when granting)
- Approval friction: Level 3 requires `--confirm CRITICAL` AND `--snapshot`
- A maximum runtime MUST be defined (`--minutes`, default 120, max 1440)
- Double confirmation: first a query, then an explicit confirmation sentence
- NO background agent — foreground only, with user supervision

**Explanation requirement:** Full briefing BEFORE EVERY command. Wait for an explicit "Continue".

**Typical tasks:** Disaster recovery, kernel upgrade, OS upgrade

### What ALWAYS stays blocked (NO override possible — not even Level 3)

- `chown -R` / `chmod -R` / `chgrp -R` directly on `/etc/`, `/usr/`, `/var/`, `/lib/`, `/bin/`, `/sbin/`, `/boot/`
- `rm -rf /`, `rm -rf ~`, `rm -rf /*`, `rm -rf .`
- `chmod 777`, `chmod -R 777`
- `mkfs`, `dd if=.* of=/dev/`, fork bomb, `curl|sh` / `wget|sh`
- **Git safety:** force-push to main/master, `git reset --hard`, `git commit --no-verify`,
  `git commit --amend`, `git add -A` / `git add .`, `git config` (writing)
- **Self-protection paths** (see above) and **owner_only commands** (see above)

---

## Granting overrides: The approval channel

The old model ("the owner says 'Level 1' in chat, the AI creates the override file
itself") no longer applies — the active override directory is self_protect, the AI
cannot write there. The new, tamper-proof flow:

1. **You recognize a need** (an action was blocked, or you know it will be).
   Determine the **lowest sufficient level** and the **minimal scope**.
2. **You write a proposal** into the pending directory
   `~/.claude/.sudo-overrides-pending/` (you may do this — it is NOT self_protect),
   with `confirmed: false`. Format see below.
3. **You explain to the owner** the level, scope, and the concrete commands
   (explanation requirement per level) and hand over the **ready-to-copy `!`
   command**:
   ```
   ! ~/.claude/bin/grant-override <id> --minutes N [--confirm LABEL] [--snapshot ID]
   ```
4. **The owner runs the command** (= their consent). Only their `!` reaches the
   script. The script sets `confirmed: true`, `label`, `expires_at` and moves the
   file into the active directory.
5. **The hook reads the activated file** and grants the scope.

`<id>` is tolerant: file name or agent id, with/without `.json`, with/without the
`agent-` prefix.

### Override directory and file format

Active: `~/.claude/.sudo-overrides/` (self_protect). Proposals: `~/.claude/.sudo-overrides-pending/`.
Each instance / each agent has its **own** file.

**NO INHERITANCE:** A subagent command carries an `agent_id` (read by the hook from
stdin). It only pulls override files whose `agent_id` matches exactly.
Coordinator / main-session overrides (without `agent_id`) NEVER apply to subagents.
Without a matching override, every subagent runs at **Level 0**.

**Main session / coordinator** — file `{name}.json` or `system-{...}.json`,
**without** an `agent_id` field. `expires_at` is MANDATORY (otherwise discarded —
hygiene against override leftovers); the approval script sets it via `--minutes`.

**Subagent** — file `agent-{agent_id}.json`, **with** `agent_id` == the hook agent_id:

```json
{
  "override_level": 1,
  "task": "Deploy Example Service v2.3",
  "project": "example-project",
  "confirmed": false,
  "agent_id": "<exact agent_id of the subagent>",
  "grants": {
    "additional_sudo": ["docker", "systemctl"],
    "allowed_paths": ["/opt/example/service"],
    "recursive_operations": false,
    "system_paths": false
  }
}
```

Mandatory fields in the proposal: `override_level` ∈ {1,2,3}, `task` (non-empty),
`confirmed: false`. Set by the script (do not fill in yourself): `confirmed: true`,
`label`, `expires_at`, `granted_at`, `granted_by`, optionally `snapshot_id`.

Grant semantics: `additional_sudo` = list of allowed commands OR `"all"` (the base
whitelist always applies in addition; Level 2+ allows all sudo anyway).
`allowed_paths` = at Level 1, the allowed write paths, path-boundary-exact
(`/opt/x` covers `/opt/x` and below, not `/opt/x-other`). The `system_paths` flag
is deliberately NOT evaluated — only the level controls system-path access.

### Rules
- An override MUST have a concrete reference (task, project, or description)
- Global overrides ("always do sudo however you like") do NOT exist
- **Cleanup:** The AI CANNOT delete active override files (self_protect).
  Either `expires_at` runs out, or the owner removes them via `! rm`.
  `expires_after: task_completion` cannot be determined by the hook itself.
- NEVER claim another's override files (agent scoping via `agent_id`)
- **Background agents may use Level 1 at most** (procedural rule —
  `run_in_background` is not visible to the hook)
- At Level 2+: ask before EVERY critical command
- At Level 3: wait for an explicit "Continue" before executing
- You may refuse implausible tasks even with a valid override (defense in depth)

---

## Hook dev mode (editing hook source files under supervision)

When the AI is supposed to change a hook source file (`command-guard.py`,
`security-rules.json`, other files in `~/.claude/hooks`), the owner temporarily
lifts self-protection ONLY for that purpose:

```
! ~/.claude/bin/hook-dev-mode on <minutes>     # enable (mandatory expiry)
! ~/.claude/bin/hook-dev-mode off              # disable
! ~/.claude/bin/hook-dev-mode status           # status
```

Dev mode releases **only** the hook source files. The override dir,
`settings.json`, `bin`, `CLAUDE.md` and `rules/` (this file!) stay hard-protected
EVEN in dev mode. If the expiry timestamp is missing or the flag file is
unparsable, protection applies (fail-closed). The owner therefore always changes
this file (`rules/`) via `!` (e.g. `cp` from a staging file), never through dev mode.

---

## Explanation requirement for override commands

For every command that runs through the override mechanism, you MUST give an
explanation that matches the override level:

- **Level 0** (Normal): a short one-liner for unusual commands
- **Level 1** (EXTENDED): WHAT you are doing + WHY
- **Level 2** (FULL): WHAT + WHY + RISK + concrete ROLLBACK command
- **Level 3** (CRITICAL): Full briefing BEFORE EVERY command.
  You wait for an explicit "Continue" before executing.

Explain in plain language. The user is not a system administrator.
Use analogies where helpful. Always name the concrete command
AND what it does to the system.

**Goal:** After every session, the user should understand more about their system
than before. You are not just a tool, but also a teacher.
