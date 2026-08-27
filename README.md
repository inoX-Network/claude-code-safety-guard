# Safety Guard — for Claude Code &amp; opencode

[![Born from a real incident](https://img.shields.io/badge/born%20from-a%20real%20incident-red)](https://github.com/anthropics/claude-code/issues/39283)
[![Works with](https://img.shields.io/badge/works%20with-Claude%20Code%20%2B%20opencode%20%2B%20Antigravity-success)](#supported-tool-chains)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A **deterministic tool-call guard** for AI coding agents. It sees every tool call *before* it runs and blocks the catastrophic ones — `rm -rf /`, reading `~/.ssh`, writing `/etc`, force-push to `main`, credential exfiltration — with a **3-level, agent-scoped override** for when you genuinely need elevated rights, and a self-protection layer so the AI can never disarm its own guard. Same input, same verdict, every time. No LLM in the loop: it's the net for when the model's judgment (or the permission prompt) fails or gets subverted by prompt injection.

- **Claude Code:** runs as a `PreToolUse` hook.
- **opencode:** runs as a plugin that bridges to the same guard — see [opencode/README.md](opencode/README.md).
- **Antigravity (`agy`):** runs as a `PreToolUse` adapter against the same guard — see [Supported tool chains](#supported-tool-chains).

> **Born from a real incident.** This started after [Claude Code executed a destructive `chown -R` on `/etc/`](https://github.com/anthropics/claude-code/issues/39283) — a multi-hour recovery. The built-in permission system wasn't enough. This is defense-in-depth.

> **Hardened by self-audit.** The guard was put through a white-box audit of its *own* code, which found five real bypasses (credential reads via `python3 -c`, `${IFS}` obfuscation, a fail-open on a missing rules file, …). All five are fixed, each with a regression test. What it deliberately does **not** try to do is documented honestly in [THREAT-MODEL.md](THREAT-MODEL.md) — it's a bouncer inside the wall, not the wall itself.

### Quickstart

```bash
# Claude Code: point a PreToolUse hook at command-guard.py (full guide in INSTALL.md)
cp security-rules.example.json ~/.claude/safety-guard/security-rules.json
# then register hooks/command-guard.py as a PreToolUse hook in ~/.claude/settings.json

# opencode: drop the plugin in and reuse the same rules — see opencode/README.md
```

> **Install:** A full, from-scratch setup guide lives in [INSTALL.md](INSTALL.md). This README explains *what* the guard does and *why*; INSTALL.md explains *how* to deploy it.

> Built and maintained by [inoX-Network](https://inox-network.de). Bug reports — especially new bypasses — are very welcome.

---

## What's new in v2

If you used the earlier version, here is what changed:

- **Six tool matchers instead of two.** The hook now guards `Bash`, `Read`, `Write`, `Edit`, `MultiEdit`, and `NotebookEdit`. The write tools are checked against protected paths **and** self-protection — they were previously a blind spot.
- **Real level differentiation.** The hook now evaluates `override_level` 0/1/2/3 individually. It is no longer "any override active → everything allowed". Paths and sudo are unlocked *per level*.
- **Agent scoping.** Subagents do **not** inherit the coordinator's or main session's override. Each agent needs its own override file bound to its `agent_id`, or it runs at level 0.
- **Self-protection.** The hook, the rules file, the rules document, the active override directory and the `bin/` scripts can never be written by the AI — no override lifts this.
- **Approval channel.** The AI can no longer write itself an override. It writes a *proposal*; only the owner activates it via an owner-exclusive script invoked through `!`.
- **Dev mode.** A supervised, time-boxed way for the owner to let the AI edit the hook *sources* — without opening up settings, the override dir, or the rules.
- **Fail-closed (breaking change).** When the rules file or input is missing/unparsable, the hook now behaves **conservatively** (blocks / discards the override) instead of allowing through.
- **Audit log.** Every decision is written to a JSONL audit log with secret redaction.
- **`expires_at` timestamps.** Overrides now end on an ISO-8601 expiry (or when the owner removes the file). The old "the instance deletes its own file" model is gone — the AI cannot delete active override files.

---

## Features

- **Blocked patterns** — `rm -rf /`, `mkfs`, `chmod 777`, fork bombs, pipe-to-shell, recursive `chown`/`chmod`/`chgrp` on system paths. **Always** blocked, even with an active override.
- **Git safety** — `git reset --hard`, force-push (incl. `--force-with-lease`), `commit --no-verify`, `commit --amend`, `git add -A` / `git add .`, and writing `git config` are **always** blocked. Force-push to `main`/`master` has its own dedicated rule on top.
- **Self-protection** — The AI cannot write the hook, the rules file, the rules document, the active override directory, or the `bin/` scripts — via Bash **or** Write/Edit. No override lifts this. It reaches beyond this repo's own files: the **shell's startup files** (`.zshrc`, `.bashrc`, `.profile`, …) are the ground every command check stands on, and the **control files of other CLIs** (opencode, Antigravity) hand out the same power one directory over.
- **Delete protection** — A second path list for paths that may be *changed* but never *removed*. Write protection would block four maintenance paths to stop one deletion; this separates the two.
- **Owner-only commands** — The approval and dev-mode scripts are hard-blocked for AI Bash calls, so the AI cannot grant itself rights.
- **Protected paths** — Level-dependent write protection for `~/.ssh`, `~/.gnupg`, `/etc/shadow`, `/boot`, `/usr/bin`, etc.
- **Credential & `.env` read protection** — The Read tool cannot reach private keys, cloud credentials, or `.env` files without a level-1+ override. Public keys and SSH config stay open.
- **3-level, agent-scoped override system** — Scoped, explicit, auditable, and per-instance.
- **Audit log** — Every allow/block decision is logged (JSONL) with secret redaction.
- **Desktop notifications** — Optional heads-up on package installs.
- **Prompt injection detection** — Warns (doesn't block) when suspicious keywords appear in a command.
- **Diagnostics register** — A second hook (`Stop` + `SessionStart`) that records language-server warnings the AI would otherwise file away, and asks for a reason instead of an acknowledgement. Five states; `fixed` is measured, not claimed. See its own section below.
- **Update check** — Optional, off by default: one line at session start when a newer version has been published. Reads and compares, nothing else.

---

## How it works

```
tool call ──► PreToolUse hook ──► command-guard.py ──► reads agent_id + tool from stdin
                                       │
        ┌──────────────────┬──────────┴───────────┬──────────────────────────┐
        ▼                  ▼                       ▼                          ▼
      Read              Write/Edit/             Bash                       other
                        MultiEdit/                                         tools
        │               NotebookEdit             │                          │
        ▼                  │                      ▼                       EXIT 0
  env / credential         ▼            ALWAYS, no override:               (allow)
  read protection    self-protection?   blocked_patterns · owner_only ·
        │            env write? path?   force-push · git-safety ·
        │                  │            self-protection
        ▼                  ▼                      │
   allow / block      allow / block               ▼
                                        load override for THIS context
                                        (agent_id → no inheritance)
                                                   │
                                                   ▼
                                        level-dependent: protected paths,
                                        sudo allowlist, notify, injection
                                                   │
                                                   ▼
                                            allow (EXIT 0) / block (EXIT 2)
```

Every branch ends by writing an audit line. `EXIT 0` allows the tool call, `EXIT 2` blocks it.

### Bash checks, in order

The first group runs **always** — an active override never weakens it:

1. **Blocked patterns** (`rm -rf /`, `mkfs`, recursive `chown` on system paths, …)
2. **Owner-only commands** (`grant-override`, `hook-dev-mode`)
3. **Force-push** to `main`/`master`
4. **Git-safety** ops (`reset --hard`, `--no-verify`, `--amend`, `add -A`/`.`, writing `config`)
5. **Self-protection** — write access to the security system's own files

Only after those does the hook load the override for the calling context and run the **level-dependent** checks:

6. **Protected paths** — level 0: none; level 1: only explicitly granted paths; level 2+: all protected paths (single ops — recursive-on-system stays hard-blocked above)
7. **Sudo allowlist** — base allowlist plus `additional_sudo` grants; level 2+ (or `additional_sudo: "all"`) allows all sudo
8. **Confirmation** desktop notification, then **prompt-injection** warning

### Read checks

1. **`.env` files** require a level-1+ override
2. **Always-blocked reads** (`/etc/shadow`, `/etc/gshadow`) — no override possible
3. **Always-allowed** files (public keys, `~/.ssh/config`, `known_hosts`, `authorized_keys`)
4. **Override-required** files (private keys, cloud credentials) — need a level-1+ override

### Write / Edit / MultiEdit / NotebookEdit checks

1. **Self-protection** — no override lifts it (only dev mode unlocks the hook *sources*)
2. **`.env` write** — requires a level-1+ override
3. **Protected paths** — same level logic as the Bash path check

---

## Protection scope

**Built for a session with no other brakes.** Everyday work here — and every
test run in this repo — happens with Claude Code's permission prompts turned
off (`bypass permissions`). That is deliberate, not sloppy: an agent that stops
every few minutes to ask is not autonomous, and a human who clicks "allow"
fifty times a day stops reading what they are allowing. This guard **replaces**
those prompts rather than adding to them. Read the scope below with that in
mind — what it does not cover, nothing else covers either.

That is also why the refusals are hard by default and the override needs the
owner: the guard is not one opinion among several, it is the only one asked.

The guard protects **zones and catastrophic patterns**, not "every write or
delete". Knowing this contract avoids surprise:

- **In scope — zones:** writes/deletes to a configured `blocked_paths_write`
  path (e.g. `/etc`, `/bin`, `~/.ssh`) or a hard-coded self-protection path are
  blocked. Detection is a **write-verb gate** (`rm`, `rmdir`, `unlink`, `shred`,
  `mv`, `cp`, `truncate`, `tee`, `ln`, `>`, `find … -delete`, `rsync … --delete`,
  `git clean`, …) combined with a boundary-accurate path match.
- **In scope — catastrophic patterns:** a small set of always-block regexes
  (`rm -rf /`, `rm -rf ~`, `chmod 777`, `mkfs`, `dd of=/dev/sd…`, fork bomb,
  `curl … | sh`, recursive `chown/chmod` on system trees, …).
- **Out of scope — default allow:** anything outside those zones and patterns is
  allowed by design. `rm -rf ~/Downloads/project` is **not** blocked — the guard
  is a guardrail against catastrophic and protected-zone operations, not a
  general "are you sure?" for ordinary file management.

### Known limitations

- **Symlinks are not resolved.** Path matching is purely lexical
  (`os.path.normpath`, no `realpath`/`readlink`) — see the `_norm_path` docstring
  ("no filesystem/symlink access, which the hook deliberately avoids"). A symlink
  in an unprotected zone whose target lives in a protected zone is matched by its
  **lexical** path, so a write *through* the link (`> safe/link`,
  `truncate safe/link`) can reach the protected target unblocked. This is a
  deliberate trade-off: resolving symlinks touches the filesystem and opens
  TOCTOU, performance, and existence questions. Tracked in
  `BEFUND-guard-scope-symlink-2026-07-24.md` (columns 3/4 of the test matrix).
- **Glob patterns are checked against the protection list, not expanded.**
  Since 2026-08-25 a write target containing `*`, `?` or `[…]` is held against
  every protected path component by component: if the pattern *could* hit one,
  it is refused. Before that the comparison was literal, so
  `echo x > ~/.claude/setting*.json` walked past the self-protection while the
  spelled-out name was refused. Expanding the pattern was rejected on purpose —
  it would touch the filesystem and reopen the TOCTOU question above. The
  remaining gap is the same one the symlink note describes: a target that only
  becomes a path *later* — through a variable, a decoder, word splitting — is
  still invisible to a text matcher. A pattern must be at least as deep as the
  protected path, otherwise a bare `*` would match everything.
- The write-verb gate is not a strict verb→path binding. It is *(a write verb)
  AND (a protected path)* **within the same segment** of the line: a write in one
  segment no longer makes a protected path in another its target, and a directory
  change, an assignment value or a line continuation still counts as part of the
  write context. Inside a single segment the coarseness remains — `sha256sum
  <protected file> > /tmp/sum.txt` is refused although only the redirect target
  is written.
- **Interpreter one-liners are matched literally, and naming one is enough.**
  The inline branch compares the expanded command text against the protected
  paths, shell assignments included — `VAR=<protected dir>; python3 -c
  "open('$VAR/x')"` is matched. (It was not until 2026-08-23: only the ordinary
  write check resolved assignments, and the two branches disagreed.) Inside this
  branch even a plain **read** is refused: `python3 -c "print(open(<control
  file>).read())"` does not get through. That bluntness is deliberate and
  measured — of 608 real refusals, 44 were `open(path,'w')`, a write with no
  shell verb and no redirection that nothing else catches. The price is ten real
  reads across seven sessions, each with `cat`/`grep`/`head` as the way out, and
  the refusal now says so instead of claiming you tried to write. Assembling a
  path from pieces still escapes the branch, but only when the split falls
  *inside* the protected part: `'/tmp/x/.clau' + 'de/settings.json'` passes,
  `'/tmp/x/.claude/settings.json'` split anywhere before it does not. That is
  the general obfuscation limit named in THREAT-MODEL.md: no substring layer
  tames a Turing-complete shell. Sandbox and least privilege are the answer to
  that one, not the hook.

---

## The 3 levels

A static blocklist isn't enough — sometimes you legitimately need extra `sudo` (system maintenance) or even recursive recovery operations. Instead of disabling the guard, the override system grants **scoped, explicit, auditable** permissions per task.

### Level 1 — EXTENDED (deployment, configuration)

- **Allowed:** write to explicitly granted paths (`grants.allowed_paths`, path-boundary-exact); extra sudo commands (`grants.additional_sudo`); single-file ops on normally protected paths.
- **Not allowed:** recursive operations on protected paths; operations on system paths (`/usr/`, `/lib/`, `/bin/`, `/sbin/`); `chown`/`chmod` on `/etc/` beyond explicitly named files.
- **Explanation duty:** WHAT + WHY.

### Level 2 — FULL (system maintenance, security fixes)

- **Additionally allowed:** write access to **all** normally protected paths; **all** sudo commands; single-file ops on system paths (e.g. `/etc/ssh/sshd_config`).
- **Not allowed:** recursive operations on system paths — never.
- **Approval friction:** `--confirm FULL` required when granting.
- **Explanation duty:** WHAT + WHY + RISK + concrete ROLLBACK command.

### Level 3 — CRITICAL (emergencies, maximum risk)

- **Additionally allowed:** recursive operations on non-system paths that could reach system paths via bind mounts.
- **Mandatory preconditions:** a snapshot created beforehand and its ID documented (`--snapshot <ID>`); `--confirm CRITICAL` **and** `--snapshot` when granting; a maximum runtime (`--minutes`, default 120, max 1440); double confirmation; foreground only, no background agent.
- **Explanation duty:** full briefing before *every* command; wait for an explicit "Continue".

At all levels, the always-blocked group (blocked patterns, git-safety, self-protection, owner-only) stays in force — level 3 included.

---

## Agent scoping

The hook reads `agent_id` from the PreToolUse stdin and uses it to pick the matching override file:

- **Main session / coordinator** → override files **without** an `agent_id` field. These require a mandatory `expires_at` (an override without expiry is discarded).
- **Subagent** → only override files named `agent-<agent_id>.json` whose `agent_id` matches **exactly**.

**No inheritance:** a subagent never sees the coordinator's override, and the main session never sees an agent-bound one. Without a matching, confirmed, unexpired override, a context runs at **level 0**. When several valid overrides match, the **highest** `override_level` wins.

---

## The approval channel

The AI **cannot** grant itself an override. The active override directory is self-protected, so the AI cannot write there. The flow is:

1. **The AI detects a need** (something was blocked, or it knows it will be) and determines the lowest sufficient level and the minimal scope.
2. **The AI writes a proposal** (`confirmed: false`) into the pending directory `~/.claude/.sudo-overrides-pending/` — which is deliberately **not** self-protected.
3. **The AI hands the owner a ready-to-copy command** and explains level + scope:
   ```
   ! ~/.claude/bin/grant-override <id> --minutes N [--confirm LABEL] [--snapshot ID]
   ```
4. **The owner runs it** (their consent). Because `grant-override` is an owner-only command, only the owner's `!` reaches it. The script sets `confirmed: true`, `label`, `expires_at`, `granted_at`, `granted_by`, then moves the file into the active directory `~/.claude/.sudo-overrides/`.
5. **The hook reads the activated file** and grants the scope until `expires_at`.

`<id>` is tolerant: a file name or agent id, with/without `.json`, with/without the `agent-` prefix. `--minutes` must be between 1 and 1440 (default 120).

---

## Dev mode

Sometimes the owner wants the AI to edit the hook *sources* themselves (the hook, the rules file). Dev mode is the supervised, time-boxed way to do that:

```
! ~/.claude/bin/hook-dev-mode on <minutes>   # default 30, max 240
! ~/.claude/bin/hook-dev-mode off
! ~/.claude/bin/hook-dev-mode status
```

Dev mode releases **only** the hook source files (`~/.claude/hooks` and the live `security-rules.json`). The active override directory, `settings.json`, `bin/`, `CLAUDE.md` and `rules/` stay hard-protected **even in dev mode** — otherwise the AI could write itself an override while editing the hook. `hook-dev-mode` is owner-only, so only the owner's `!` reaches it. **Fail-closed:** if the flag file's `expires_at` is missing/expired or the flag is unparsable, dev mode is treated as OFF.

---

## Self-protection

These paths can never be written by AI tool calls — neither via Bash nor via Write/Edit. **No override lifts this** (only the owner via `!`, or, for the hook sources only, an active dev mode):

| Protected path | What it is |
|----------------|------------|
| `~/.claude/.sudo-overrides` | active override directory |
| `~/.claude/bin` | approval & dev-mode scripts |
| `~/.claude/hooks` | the hook sources (dev-mode-unlockable) |
| `~/.claude/safety-guard/security-rules.json` | the live rules (dev-mode-unlockable) |
| `~/.claude/.hook-dev-mode` | the dev-mode flag file |
| `~/.claude/settings.json`, `~/.claude/settings.local.json` | Claude Code settings |
| `~/.claude/CLAUDE.md` | AI context file |
| `~/.claude/rules` | the rules document(s) |

The list is hardcoded in the hook (not in the JSON rules) on purpose: if it lived in the rules file, the protection list could be edited through itself. The pending directory `~/.claude/.sudo-overrides-pending` is **deliberately not** protected — the AI must be able to drop proposals there.

**A neighbour is not the path.** Every protected entry is matched with a path
boundary, so a directory whose name merely *starts* with a protected one stays
free: `~/.claude/.sudo-overrides-pending` (proposals), a `.zshrc.bak`, a
`hooks-old/`. Without that boundary the prefix match drags them all in.

This matters more than it sounds, because the guard has **two** places that
compare against this list: the ordinary write check, and a separate branch for
interpreter one-liners (`python3 -c`, `node -e`) — inline code carries no shell
write indicator and no token boundary, so a path inside `open("...")` has to be
matched as a substring. Both branches need the boundary. For a while only one
had it, and the branch that lacked it refused exactly the thing the paragraph
above promises: dropping and checking an override proposal. **The guard was
blocking the use of its own escalation path.**

### The shell's startup files

The same list also covers the shell startup files, and for a reason worth stating plainly: this guard judges the **text** of a command. What a name means in the shell that actually runs it, the guard cannot see. One line —

```sh
function python3() { ... }
```

— in a startup file turns every later `python3 ...` into something else, while the guard keeps reading the harmless text and letting it through. That is not a way around one rule; it is the ground under all of them.

| Protected | |
|---|---|
| zsh | `~/.zshenv`, `~/.zprofile`, `~/.zshrc`, `~/.zlogin`, `~/.zlogout` |
| bash | `~/.bash_profile`, `~/.bash_login`, `~/.bashrc`, `~/.bash_logout` |
| sh | `~/.profile` |
| fish | `~/.config/fish/config.fish`, `~/.config/fish/conf.d/` |

**Reading stays free** on every route — `cat`, `grep`, `sed -n`, `Read`, and copying a backup *outward*. A protection that locks you out of inspecting your own shell keeps you from proving a finding, and gets switched off. Only writing blocks.

Two things worth knowing before this surprises you:

- A backup **next to** a protected file is fine (`cp ~/.zshrc ~/.zshrc.bak` — the `.bak` carries a different name and is not a startup file). A backup **into** a protected directory is not (`conf.d/a.fish.bak` lands inside `conf.d/`).
- The system-wide equivalents (`/etc/profile`, `/etc/zsh/*`, `/etc/profile.d/`) are not in this list because they already block via the system-path guard.

Why hard rather than level 1: the chains are listed in full, including links nobody has ever written to, because half a chain is an open door — whoever cannot write `.zshrc` writes `.zlogin`. On the machine this was built for, six of the seven files had **zero** writes in 2.5 months of audit log, and `~/.zshrc` had twelve, eight of them from a single clean-up session. A block that is hit roughly twice a month does not get switched off. Your own `!` bypasses the guard regardless.

If your setup does touch these files often, `~/.zshrc` is the one to consider moving to level 1 — it was the only one with any measured traffic at all.

### Control files, wherever they lie

The list above is anchored to the home directory. The tool chain reads control
files out of **every project directory** as well, and a settings file there
grants permissions and registers hooks just the same. So this part is a rule,
not a list of places — a project created tomorrow is covered without anyone
adding it:

| Pattern | Strength |
|---|---|
| `.claude/settings.json`, `.claude/settings.local.json` | hard |
| `.claude/hooks/` | hard |
| `.mcp.json` | hard |
| `.claude/agents/`, `.claude/skills/`, `.claude/commands/` | level 1 |

A project's own `CLAUDE.md` is deliberately **not** here. 70 writes in two
months make it everyday work, and a barrier would be switched off within the
week; its counterweight is version control — see THREAT-MODEL.

### The second tool chain

If another agent CLI runs on the same machine, its control files are a way
around this guard too — crosswise: Claude Code writes, the other CLI executes.
For opencode that is not theoretical, because this project ships the adapter
itself, and `~/.config/opencode/plugin/safety-guard.ts` is what establishes the
protection over there:

| Pattern (project-local `.opencode/` and global `~/.config/opencode/`) | Strength |
|---|---|
| `plugin/`, `plugins/`, `tools/` | hard |
| `opencode.json`, `opencode.jsonc` (matched by name, like `.mcp.json`) | level 1 |
| `agent(s)/`, `command(s)/`, `skills/` | level 1 |

`AGENTS.md` stays free, for the same reason as `CLAUDE.md`. `themes/` and the
runtime data under `~/.local/share/opencode/` are not control and stay free
too.

**What this costs you:** installing or updating the opencode adapter is now an
owner action — `!` or dev mode — because it writes into a hard-protected
directory. That is the point rather than a side effect: nothing else should be
able to replace the file that does the guarding.

### The third tool chain — Antigravity (`agy`)

The same reasoning covers Antigravity, and it held before any adapter
existed — self-protection of a chain's control files does not depend on
that chain being wired up. Since 2026-08-23 an adapter exists as well; see
*Supported tool chains* below. Its `hooks.json` is the sharp end: the
documentation embedded in the binary lists it under *"Lifecycle Event —
running scripts/commands at specific agent lifecycle points (e.g. pre-tool
execution)"*. That is the exact counterpart to `.claude/hooks/`, and
Antigravity brings no guard of its own.

| Pattern | Strength |
|---|---|
| `~/.gemini/{config,antigravity-cli}/hooks.json` | hard |
| `~/.gemini/config/mcp_config.json`, `plugins/`, `plugins.json` | hard |
| `~/.gemini/config/projects/` (takes precedence over the global setting) | hard |
| `~/.gemini/config/config.json` (enables plugins shipped disabled) | hard |
| `~/.gemini/{settings,trustedFolders}.json`, `antigravity-cli/settings.json` | hard |
| `~/.gemini/config/` — everything else there | level 1 |
| project-local `[._]agents?/`: `hooks.json`, `mcp_config.json`, `plugins/` | hard |
| project-local `[._]agents?/`: `skills/`, `rules/`, `agents/`, `workflows/` | level 1 |

All four spellings of the workspace root are documented and covered:
`.agents/`, `.agent/`, `_agents/`, `_agent/`.

`AGENTS.md` and `GEMINI.md` stay free, for the same reason as `CLAUDE.md`.
Runtime data under `~/.gemini/antigravity-cli/` — `conversations/`, `brain/`,
`history.jsonl`, `log/`, `cache/` — is not control and stays free too.

Two cuts are worth spelling out, because both were tempting to get wrong:

- **No blanket pattern on `.agents/`.** That directory is also the sub-agents'
  working directory (`ORIGINAL_REQUEST.md`, `phase_*_results.json`,
  `segment_*/handoff_*.md`). Locking it wholesale would cripple the CLI, so
  only the named subdirectories are covered.
- **One catch-all at level 1 for `~/.gemini/config/`.** That directory *is* the
  documented global customization root and holds no runtime data, so a broad
  pattern is safe there — and it also covers whatever a future release puts
  in it. Enumerating only today's files has already cost us once.

---

## Audit log

Every decision (allow or block, by Bash/Read/Write/Edit/… or by the owner scripts) is appended as one JSON line to:

```
~/.claude/.agent-audit/actions.jsonl
```

Fields: `ts`, `session_id`, `actor` (the `agent_id`, or `main` for the main session), `agent_type`, `tool`, `target`, `decision`, `reason`, `level`. Before the `target` (the command or file path) is logged it runs through **secret redaction** — passwords, tokens, `key=value` secrets, `--password`/`--token` flags and `Authorization:` headers become `[REDACTED]`, and the field is truncated to 600 characters. Logging failures never block the guard.

### Reading it

A log nobody reads is a log nobody has. [`tools/guard-audit.py`](tools/README.md) turns the JSONL into three views — which overrides were granted and for what, which actions were blocked and why (grouped by reason), and blocks/overrides per day. Read-only, standard library only, no access to protected directories.

```bash
python3 tools/guard-audit.py                 # all views, terminal, English
python3 tools/guard-audit.py --lang de       # German
python3 tools/guard-audit.py --blocks        # blocks only
python3 tools/guard-audit.py --html          # HTML report, ~/.cache/guard-audit/report.html
```

The HTML report is **sanitized by default** — commands, paths and task descriptions are reduced to their shape, so a report can be shared or filed without leaking what you were working on. `--full` keeps the real values; that file belongs nowhere near a repository.

The block report is the interesting one, and not only for security: **the false alarms are the more valuable half.** They show where the guard's model of legitimate work does not match reality — the only feedback that calibrates limits nobody knew about when the rules were written. See [tools/README.md](tools/README.md) for all options.

---

## Credential & `.env` read protection

The hook intercepts Read (and `.env` writes) and applies tiers:

| Tier | Behavior | Examples | Override |
|------|----------|----------|----------|
| **Always allowed** | no restriction | `~/.ssh/*.pub`, `~/.ssh/config`, `~/.ssh/known_hosts`, `~/.ssh/authorized_keys` | not needed |
| **Override required** | blocked without level 1+ | `~/.ssh/id_*`, `~/.aws/credentials`, `~/.aws/config`, `~/.npmrc`, `~/.docker/config.json`, `~/.gnupg/` | level 1+ |
| **`.env` files** | read **and** write require level 1+ | `.env`, `.env.local`, `.env.development`, `.env.production` (matched by basename, any directory) | level 1+ |
| **Always blocked** | cannot be read | `/etc/shadow`, `/etc/gshadow` | none |

Without this, a prompt-injection or confused-deputy attack could trick the AI into reading your private key or `.env` and exfiltrating it via a later command.

---

## What's always blocked

No override unlocks any of these:

| Category | Examples / patterns |
|----------|---------------------|
| Catastrophic `rm` | `rm -rf /`, `rm -rf ~`, `rm -rf /*`, `rm -rf .`, `rm -rf $HOME` |
| Permission destruction | `chmod 777`, `chmod -R 777` |
| Drive overwrite | `mkfs`, `dd if=… of=/dev/{sd,nvme,hd}`, `> /dev/sd` |
| Recursive on system paths | `chown -R` / `chmod -R` / `chgrp -R` on `/etc`, `/usr`, `/var`, `/lib`, `/bin`, `/sbin`, `/boot` — the exact pattern from [the incident](https://github.com/anthropics/claude-code/issues/39283) |
| Remote-code execution | `curl … \| sh`, `wget … \| bash`, `eval … base64`, `python -c … import os … system` |
| Fork bomb | `:(){ :\|:& };:` |
| Git safety | `git reset --hard`, force-push (`-f` / `--force` / `--force-with-lease`), `commit --no-verify`, `commit --amend`, `git add -A` / `git add .`, writing `git config` |
| Force-push to primary | `git push --force` / `-f` / `--force-with-lease` to `main` / `master` (dedicated rule) |
| Self-protection paths | the hook, rules file, rules doc, active override dir, `bin/` (see above) |
| Owner-only commands | `grant-override`, `hook-dev-mode` (AI Bash calls) |
| Credential reads | `/etc/shadow`, `/etc/gshadow` |

---

## Installation settings & language

Two files, two jobs. **`security-rules.json`** says *what* is allowed — the section below covers it. **`~/.claude/guard-config.json`** says where this machine keeps things, and in which language the guard speaks. It is entirely optional: without it the guard runs on its defaults, in English. See [guard-config.example.json](guard-config.example.json).

```json
{
  "version": 1,
  "language": "de",
  "installation": {
    "rules": "~/.claude/safety-guard/security-rules.json",
    "hook_source": "~/.claude/hooks"
  }
}
```

| Key | Effect |
|-----|--------|
| `language` | Message language. Omit it and everything is English. |
| `installation.rules` | Where the rules file lives — the hook **loads** from here, and the path is added to self-protection. |
| `installation.hook_source` | Where the hook's own sources live. Does not change what runs; adds the directory to self-protection, and dev mode opens exactly it. Set it when the installed hook is a symlink into a checkout. |
| `installation.dev_window` | Flag file for dev mode. Default `~/.claude/.hook-dev-mode`. |
| `installation.lang_dir` | Where the language files live, if not next to the hook. |

### A different language

English is **built into** the hook and always available — a single file gets copied to its place, and a guard falling silent because a language file did not travel with it would be worse than an ugly message. Another language is a setting, not a fork:

1. put `lang/<code>.json` next to the hook (`de.json` ships with this repo), or point `installation.lang_dir` at the directory
2. set `"language": "<code>"` in `guard-config.json`

Missing keys fall back to English, so a half-finished translation still works. A key that is not in the catalogue at all prints the key plus its values rather than nothing — a refusal nobody can act on is worse than an ugly one.

**The wording never decides anything.** Messages carry no verdict of their own; the guard's behaviour is identical in every language. That is worth stating because it once was not: an earlier version read its own English message text back to decide whether a refusal could be overridden, which silently changed behaviour for anyone running a translation.

---

## Update check

A guard that cannot be updated goes stale, and a stale guard does not know the
bypasses that have since become known. The hook ships with a second, tiny hook
that answers one question at session start: is there a newer published version
than the one installed here?

It is **off by default** and it says so exactly once, so the feature is
discoverable without nagging. Turn it on in `guard-config.json`:

```json
{
  "update_check": {
    "enabled": true,
    "interval_hours": 24,
    "source": "https://raw.githubusercontent.com/inoX-Network/claude-code-safety-guard/main/VERSION"
  }
}
```

| Key | Effect |
|-----|--------|
| `update_check.enabled` | Off unless this is exactly `true`. While off, the guard mentions the feature once and then stays quiet. |
| `update_check.interval_hours` | How often to ask at most. Default 24. A second session start inside the window stays silent. |
| `update_check.source` | Where the published version is read from. **Must be `https://`** — an unencrypted answer could be tampered with in transit, and this one decides what you are told about your security tooling. A plain-http value falls back to the default. |

Register it as a **SessionStart** hook — it is a different hook from the guard
itself, and forgetting this is the easy mistake: the setting sits in the config,
nothing runs, and nothing complains.

```json
{
  "hooks": {
    "SessionStart": [
      { "hooks": [ { "type": "command", "command": "python3 ~/.claude/hooks/update-check.py" } ] }
    ]
  }
}
```

What it does: compares the `VERSION` file next to the hook against the published
one (both are dates — `2026.08.21` — so string order is date order) and prints
one line if the published one is newer. What it does not do: download anything,
change anything, or run with elevated rights. It reads, compares, and speaks.

Without a `VERSION` file next to the hook there is nothing to compare, and it
stays silent rather than guessing.

---

## The diagnostics register — a second hook

`hooks/diagnostics-register.py` is **not** a security check. It is in this repo
because it answers the same kind of question with the same kind of mechanism:
what does an AI do reliably wrong, and what can be put in its way?

### The problem it solves

Language-server warnings arrive as an **attachment**, not as an answer. The
filter "not my change, pre-existing code" is right most of the time and
therefore runs automatically — and that is exactly when it takes the one real
warning with it.

The measured cost, in this repo: `"delete_only" is possibly unbound` was shown
twice on the same day, on two different working copies, directly under the edit
result. Filed away both times. It was a crash in the most common branch of the
write check, and it survived 13 local test lists and 2993 test cases here,
because a crash and a considered denial exit with the same code. Someone else
had to trip over it.

A resolution cannot fix that, because nothing about it is a decision. A hook
can.

### The five states

| state | who sets it | why |
|---|---|---|
| `open` | the hook, automatically | starting state |
| `fixed` | **nobody** — the tool runs pyright and looks | a measurement, not a claim. Harder to forge than a marking, and it keeps the owner out of the common case entirely |
| `parked` | the AI, with a **reason and a deadline** | "it goes away once X lands" is a real case. The deadline is the price: parking is a postponement, not a disappearance |
| `dismissed` | **the owner only** | the single path on which a real warning falls silent for good — whoever may walk it alone can switch the hook off |
| `moot` | nobody — the file is gone | a finding, not a decision. Not deleted: if the file returns and the warning with it, it is recorded again |

Whatever stays `open` is presented once every 24 hours — **the oldest case
concretely**, with file, line and how long it has been standing. Not a count. A
message saying "3 open items" is the same wallpaper in two weeks that the
warnings themselves are today.

### Why the filter is on the rule name, not the severity

This is the number that decides whether such a hook survives contact with
everyday work. Measured over 15942 real diagnostics from 570 transcripts:

```
Error    8964      <- of these, 3720 are reportMissingImports (41%)
Hint     6954
Warning    24
```

`reportMissingImports` is pyright not finding the virtual environment while the
file is perfectly fine. **A hook keyed on severity fires on almost every edit
and is switched off within a week.**

The four rules it does watch — `reportPossiblyUnboundVariable`,
`reportUndefinedVariable`, `reportRedeclaration`,
`reportSelfClsParameterName` — are decidable without import resolution,
checkable in seconds, and a hit is nearly always a real defect. Together they
are **2.1 percent** of all diagnostics. Over 30 days that worked out to roughly
two entries per week that actually needed presenting.

### Installing it

```jsonc
// ~/.claude/settings.json
"hooks": {
  "Stop":         [{ "hooks": [{ "type": "command",
                     "command": "python3 ~/.claude/hooks/diagnostics-register.py stop" }] }],
  "SessionStart": [{ "hooks": [{ "type": "command",
                     "command": "python3 ~/.claude/hooks/diagnostics-register.py start" }] }]
}
```

Needs `pyright` on the PATH. To keep the AI from editing the register
directly, add its directory to `blocked_paths_write` in your rules — the AI
then reaches it only through the tool, and the tool enforces the state rules.

### Two things worth knowing before you build on it

**The anchor is `Stop`, not `PostToolUse`.** Measured: at the moment a
`PostToolUse` hook on an edit runs, the diagnostics do not exist yet — the
language server has not answered. They appear in the transcript a few seconds
later. The timing is not deterministic either (sometimes they arrive with the
edit, sometimes only with the next tool call), which makes `Stop` the latest
and only reliable point.

**It guards against negligence, not against intent.** Anyone assembling the
register path at runtime writes past it — the same limit self-protection has,
named in THREAT-MODEL.md. That is the right trade: the opponent here is one's
own autopilot, not an attacker.

---

## Configuration reference

The hook reads its rules from `~/.claude/safety-guard/security-rules.json` (see [security-rules.example.json](security-rules.example.json) for a complete starting point), or from wherever `installation.rules` points. Top-level keys:

| Key | Type | Description |
|-----|------|-------------|
| `blocked_patterns` | `string[]` | Always-blocked patterns. Each entry is treated as a regex if it contains regex metacharacters, otherwise as a literal substring. A literal pipe must be written `\|`. |
| `owner_only_commands` | `string[]` | Commands only the owner may run via `!`; hard-blocked for AI Bash. Matched at the **command position**, so the same name stays usable as text — in a search pattern, a note, or a file name. See below. |
| `blocked_git_ops` | `string[]` | Always-blocked git operations (regex). |
| `blocked_paths_write` | `string[]` | Paths protected from writes (supports `~`); level-dependent. |
| `blocked_paths_delete` | `string[]` | Paths that may be **changed but not destroyed** (supports `~`); level-dependent. See below. |
| `allowed_sudo` | `string[]` | Base allowlist of commands permitted after `sudo`. |
| `require_confirmation` | `string[]` | Substrings that trigger a desktop notification. |
| `protected_reads.always_allowed` | `string[]` | Read tool may always access (supports `*` globs). |
| `protected_reads.require_override_1` | `string[]` | Read needs a level-1+ override. |
| `protected_reads.always_blocked_reads` | `string[]` | Never readable, no override. |
| `protected_reads.env_files_require_override_1` | `string[]` | `.env` filenames whose read **and** write need level 1+. |
| `blocked_bash_patterns_force_push` | `string[]` | Regexes blocking force-push on `main`/`master`. |
| `prompt_injection_keywords` | `string[]` | Keywords that emit a stderr warning (no block). |
| `protected_git_branches` | `string[]` | Branches on which `git commit` is refused outright. The hook asks git for the real branch (`rev-parse`), so `git -C <path>` and `cd <path> && git commit` are covered. Merge and pull stay free. |
| `mcp_policy.gate_servers` | `string[]` | MCP servers whose every tool call needs a level-1+ override. |
| `mcp_policy.safe_servers` | `string[]` | MCP servers whose calls are free. |
| `mcp_policy.read_verb_prefixes` | `string[]` | For any other server: a tool whose name starts with one of these is treated as reading and stays free; everything else needs level 1+ (default-deny for writes). |

> The self-protection path list is **not** in this file — it is hardcoded in the hook so it cannot be edited through itself.

### Override file format

A proposal you write into the pending directory:

| Field | Type | Set by | Description |
|-------|------|--------|-------------|
| `override_level` | `1 \| 2 \| 3` | you | Permission level (must be an int, not bool). |
| `task` | `string` | you | Non-empty description of what it's for. |
| `project` | `string \| null` | you | Optional associated project. |
| `confirmed` | `boolean` | you `false` → script `true` | The hook only honors `true`. |
| `agent_id` | `string` | you | **Subagent only** — must equal the subagent's `agent_id`. Omit entirely for the main session. |
| `expires_at` | ISO-8601 | the script (`--minutes`) | Mandatory for main-session overrides; optional but honored for agent overrides. |
| `label` | `string` | the script | `EXTENDED` / `FULL` / `CRITICAL`. |
| `granted_at`, `granted_by` | string | the script | Audit metadata. |
| `snapshot_id` | `string` | the script (`--snapshot`) | Level 3 only. |
| `grants.additional_sudo` | `string[] \| "all"` | you | Extra sudo commands (base allowlist still applies). |
| `grants.allowed_paths` | `string[]` | you | Level-1 write paths, path-boundary-exact. |
| `grants.recursive_operations` | `boolean` | you | Informational. |
| `grants.system_paths` | `boolean` | you | Informational — **not evaluated** by the hook; only the level controls system-path access. |

---

## FAQ

**Q: Does this replace Claude Code's built-in permission system?**
A: No. It runs *alongside* it as an extra layer that catches dangerous patterns before they reach the permission prompt.

**Q: Can the AI grant itself an override?**
A: No. It can only write a *proposal* into the pending directory. Activation requires the owner to run the owner-only `grant-override` script via `!`, which bypasses the guard. The active override directory is self-protected.

**Q: What happens if the rules file is missing or broken?**
A: The hook is **fail-closed**. A missing rules file means no Bash rules can be evaluated; an unparsable override or input is discarded rather than trusted. (This is a breaking change from the earlier fail-open behavior.)

**Q: Do subagents inherit my session's override?**
A: No. Overrides are scoped by `agent_id`. A subagent needs its own `agent-<agent_id>.json` override, or it runs at level 0.

**Q: How does an override end?**
A: When its `expires_at` passes, or when the owner removes the file via `! rm`. The AI cannot delete active override files.

**Q: Why is force-push to main/master always blocked?**
A: Rewriting history on a primary branch is almost always a mistake when done by an AI agent. Do it manually outside Claude Code if you truly need to.

**Q: Can the AI read my private SSH key or `.env`?**
A: Not without an explicit level-1+ override. Public keys (`*.pub`) and `~/.ssh/config` are always allowed. This now also covers the Bash path — `cat`/`base64`/`cp`-source/`dd if=`/`xxd`/`head` on a protected path are blocked, not just the Read tool. It also covers **directory-level exfiltration**: handing a whole credential directory to a recursive reader (`tar`/`zip`/`rsync`/`gpg`/`scp`/`grep -r ~/.ssh` …) is blocked even though no individual key file is named, while metadata-only commands (`ls`/`find`/`stat` on the directory) stay allowed. The Bash check resolves **direct** path references; variable indirection (`X=key; cat $X`) and interpreter string literals (`python -c "open(...)"`) stay outside its scope — the same inherent limit as `blocked_patterns`. It's defense-in-depth covering the realistic attack path, not a watertight guarantee.

**Q: Does prompt-injection detection block anything?**
A: No — it only writes a warning to stderr. It's a heads-up, not a hard block.

### Changed, but not destroyed

`blocked_paths_write` is all-or-nothing: protect a directory and you also lose
the ability to write a single file inside it. For data you keep *and* maintain
— a memory store, a notes directory, an archive you append to — that is the
wrong trade, and it is the trade that gets the barrier switched off within the
week.

`blocked_paths_delete` covers the other half. It blocks the verbs that destroy
(`rm`, `rmdir`, `unlink`, `shred`, `truncate`, `mv`, `dd`, plus `find -delete`,
`rsync --delete`, `git clean`, and interpreter one-liners like
`shutil.rmtree`), while writing, editing and appending stay free. Redirects
deliberately do **not** count: `echo x > file` overwrites, but it is the
ordinary maintenance path.

`mv` counts as destroying because nothing remains at the origin — a move is a
delete as far as the source is concerned.

Measured on a real machine before shipping this: with `~/.claude/projects` in
`blocked_paths_write`, four of four maintenance paths were blocked. With it in
`blocked_paths_delete`, replaying 963 real audit-log calls, **4 became blocked
and none became allowed** — two genuine deletions and two false positives from
a `cd` prefix that shares its line with a delete verb.

Level 1 lifts it for explicitly named paths, like the write list.

### A name is not a call

`owner_only_commands` protects the approval channel itself: the AI must never
run the grant-override script or the dev-window switch, or it could approve
itself. That part is not negotiable and has no override.

What *is* negotiable is how the name is recognised. Searching the whole line
for it turns every mention into a rejection — and the mentions are constant,
because the flag file is usually named after the command. Measured on a real
machine: of nine harmless forms, eight were rejected. Reading the flag file,
`ls` on it, the name in a note, the name as a search pattern. The block did
not prevent the call; it prevented *checking whether an approval exists*.

The name is therefore matched at the **command position** of each segment,
after privilege elevation, environment assignments and options, and compared
by base name so a full path hits the same. If something else holds that
position, what it is decides: a pure print or read tool (`cat`, `ls`, `grep`,
`echo`, `head`, …) executes nothing, so the name behind it is text. Anything
else counts as executing, and there the name is searched throughout the
segment — which catches `bash -c`, `timeout`, `watch`, `xargs` and every
wrapper that has yet to be invented. There is deliberately **no allowlist of
wrappers**; that direction fails open.

Three tools that look like text tools are excluded on purpose: `awk` (can
execute via `system()`), `sed` (via the `e` flag) and `git` (via
`-c alias.x='!cmd'` or the pager). Writing a commit message that mentions such
a name works the recommended way anyway — put the message in a file.

Replaying 77718 distinct logged commands: **20 previously rejected commands now
pass, across 18 sessions, and none is newly blocked.**

---

## Supported tool chains

One guard, several front ends. The guard itself never changes for a new CLI —
what changes is the thin adapter that translates that CLI's dialect into the
guard's, and back.

| | Claude Code | opencode | Antigravity (`agy`) |
|---|---|---|---|
| **How it hooks in** | native `PreToolUse` hook | plugin (TypeScript) | adapter (Python) |
| **Where it lives** | `hooks/command-guard.py` | `opencode/plugin/safety-guard.ts` | not published yet — see below |
| **How "blocked" is said** | exit code `2` | thrown error | `{"decision":"deny"}` on stdout |
| **Tools mapped by name** | all (native payload) | 4 (`bash`, `read`, `write`, `edit`) | 21 of 57 |
| **Unmapped tools** | — | pass through | fail-closed if they carry a path, command or code argument |
| **Its own control files protected** | yes | yes | yes |
| **Far side is fail-closed** | yes | yes | yes, measured |

**"Tools mapped by name" is not a quality score.** A chain with four tools needs
four mappings. Antigravity exposes 57, and mapping every one of them would be
the wrong move: a list of everything dangerous is a list you will one day
forget to extend. What catches the rest is the fail-closed rule — an unknown
tool carrying a path, a command or a code argument is refused, whether anyone
has heard of it or not.

### How to know what a CLI really exposes

Ask it, don't read about it. Antigravity's own documentation and its internal
constants disagreed about tool names, and both were partly wrong. The
authoritative list came from the CLI itself:

```sh
echo '{"prompt":"x"}' | agy --input-format stream-json --output-format stream-json
```

The first event it emits carries the complete tool list of the running build.
Measured on 2026-08-23, that list decided four open questions at once — and
revealed four tools that were slipping past an adapter everyone believed
complete.

**This belongs in the acceptance check of every new CLI version.** It costs one
call. A tool that arrives with an update is otherwise silently unguarded.

### Antigravity: built and measured, not yet published

The adapter runs and is measured — 19 of 19 against the live chain, both
directions — but it is not in this repository yet. Its comments are the part
worth having, and they are still in the author's language; publishing the code
without them would ship a shell. Until then, the contract below is enough to
build one, and Antigravity's control files are protected either way.

### What a front end inherits

An editor or IDE that drives one of these CLIs inherits its protection
unchanged — the guard sits at the tool call, below anything a UI does. Nothing
extra to install, and nothing extra to get wrong.

## Wiring up another CLI — the integration contract

Today, anyone writing an adapter for a third CLI has to read the core to find
out what it wants. This section is that answer, so the next one is clerical
work rather than surgery.

The shape is fixed: **the core decides, the adapter translates.** An adapter
maps tool names and turns a return code into whatever "blocked" means in its
protocol. It never decides whether something is safe.

Why not teach the core a second protocol instead? Because the risk is
asymmetric. A broken adapter blocks, and the caller sees the error. A broken
format detector *inside* the core lets things through: a payload of format A
mistaken for format B comes back as exit 0 — a denial silently turned into
permission. The core keeps exactly one exit for that reason.

### What the core expects on stdin

One JSON object:

```json
{
  "tool_name": "Bash",
  "tool_input": { "command": "rm -rf /etc" },
  "session_id": "optional",
  "agent_id": "optional"
}
```

- `tool_name` — one of the tool names the core knows: `Bash`, `Read`, `Write`,
  `Edit`, `MultiEdit`, `NotebookEdit`, and the `mcp__*` family. Map your CLI's
  names onto these.
- `tool_input` — the payload. `command` for `Bash`, `file_path` for everything
  that touches a file.
- `session_id` / `agent_id` — optional, and they matter: overrides are bound to
  them. Omitting `agent_id` is the safe choice, because the call is then
  treated as a main session at level 0 and inherits nothing.

**Resolve paths to absolute before the core sees them.** A relative
`../../.claude/settings.json` cannot be matched against the self-protect list,
and the core would wave it through. Resolving is the adapter's job because only
the adapter knows the working directory.

### What it answers

| exit | meaning |
|---|---|
| `0` | allowed — run the tool call |
| `2` | blocked — the reason is on stderr, verbatim, for the user |

There is no third value. `sys.exit(0)` and `sys.exit(2)` are the only exits in
the core, so **anything else is a failure state, never a quiet yes.**

**But `2` is ambiguous, and that costs more than it looks.** The core catches
unexpected errors in itself and exits fail-closed — with the same `2`. That is
right for safety: without the net, every crash would be a silent pass. It also
means **a crash is indistinguishable from a considered denial** for anything
that checks the exit code, which is what a test suite does.

We learned this the expensive way. A crash in the *most common* branch of the
write check survived 13 local test lists and 2993 test cases here, because every
one of them asserted "blocked" and got it. The user saw a stack trace instead of
"which path, which grant is missing" — fail-closed held, the *explanation* was
lost.

If you write tests against this guard, assert on the **reason**, not only the
exit code: a denial that carries a crash marker is not a denial. See
`tests/test_no_crash_on_real_paths.py`, which does exactly that across eight
protection classes and in both languages.

The general lesson outstrips this project: **wherever something catches
fail-closed, it needs a second measurement that makes the caught thing
visible.** A safety net that swallows errors also hides them.

### The four duties of an adapter

**1. Make no security decision.** Map names, translate return codes. No "this
one looks harmless, I'll skip it". The moment an adapter starts judging, there
are two policies to keep in sync, and the weaker one wins.

**2. Block on anything that is not 0.** Not just on 2. Measured against damaged
copies of the guard:

| state of the guard file | exit | an adapter checking `== 2` |
|---|---|---|
| intact, blocks | 2 | blocks — correct |
| syntax error on line 1 | 1 | **lets it through** |
| empty file | 0 | **lets it through** |
| killed by a signal | `null` | **lets it through** |

The syntax error is the worst: it ends Python *before a single line runs*, so
the core's own fail-closed handler never gets a turn. An interrupted copy
switches the protection off in silence.

The empty file is the one failure a return code cannot reveal, since 0 means
allowed. Check the file's size instead. **Named limit:** that catches the broken
guard, not the tampered one — a guard trimmed down to `pass` also returns 0 and
looks identical from outside. What answers that is self-protection on the guard
source, not the adapter.

**3. Catch your own errors into a deny.** If the host CLI is not fail-closed —
a crashing hook, unreadable output, a timeout — the adapter must turn its own
failure into a block instead of dying. Measure this before you assume it: how
the host behaves when its hook misbehaves decides how much the adapter has to
carry.

**4. Know which tools you are *not* checking, and why.** "Block unknown tools"
is too blunt: a CLI has tools the core has no rules for, and blocking `glob`
would make every session useless. The core solves it the other way round, and
an adapter should copy that: keep a list of the tools that **only read**
(`_READ_ONLY_TOOLS` in the core), and treat everything else as potentially
writing. A tool that is not on the harmless list must either be mapped or
blocked — never skipped by default. That way a tool nobody has thought of yet
gets checked instead of waved through.

There is one deliberate fail-open: if no guard is installed at all, the adapter
warns and passes. Blocking there would make the CLI unusable for anyone who
hasn't set the guard up, and it is not a hole an attacker can create — they
would have to delete the guard first, which self-protection already covers.

### Worked example

`opencode/plugin/safety-guard.ts` is a complete adapter in 337 lines, and
the core was never touched for it. It maps four tools onto the core's names,
handles the multi-file `apply_patch` by sending every target path through
separately, resolves relative paths against the project directory first, and
blocks on every non-zero return.

Its tests are the more useful part to copy:
`opencode/test_broken_guard_denies.mjs` drives the **real** plugin function
against deliberately damaged guard copies. A rebuilt call path would not have
found any of the holes above, because the hole was in the real one.

---

## Contributing

Issues and PRs welcome. If you've been bitten by a similar incident and have patterns to add to the blocklist, please share them.

Before opening a PR, run the test suite (no install needed — the tests isolate their own runtime state):

```bash
python3 tests/test_command_guard.py
python3 tests/test_freigabe_e2e.py
```

See [INSTALL.md](INSTALL.md#e-verify-its-armed) for how to verify a live installation.

## License

[MIT](LICENSE)

---

*Born from a real incident. Built to prevent the next one.*
