# Safety Guard — for Claude Code &amp; opencode

[![tests](https://github.com/inoX-Network/claude-code-safety-guard/actions/workflows/tests.yml/badge.svg)](https://github.com/inoX-Network/claude-code-safety-guard/actions/workflows/tests.yml)
[![Born from a real incident](https://img.shields.io/badge/born%20from-a%20real%20incident-red)](https://github.com/anthropics/claude-code/issues/39283)
[![Works with](https://img.shields.io/badge/works%20with-Claude%20Code%20%2B%20opencode%20%2B%20Antigravity-success)](docs/tool-chains.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A **deterministic tool-call guard** for AI coding agents. It sees every tool call *before* it runs and blocks the catastrophic ones — `rm -rf /`, reading `~/.ssh`, writing `/etc`, force-push to `main`, credential exfiltration — with a **3-level, agent-scoped override** for when you genuinely need elevated rights, and a self-protection layer so the AI can never disarm its own guard. Same input, same verdict, every time. No LLM in the loop: it's the net for when the model's judgment (or the permission prompt) fails or gets subverted by prompt injection.

- **Claude Code:** runs as a `PreToolUse` hook.
- **opencode:** runs as a plugin that bridges to the same guard — see [opencode/README.md](opencode/README.md).
- **Antigravity (`agy`):** runs as a `PreToolUse` adapter against the same guard — see [Supported tool chains](docs/tool-chains.md).

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

## Features

- **Blocked patterns** — `rm -rf /`, `mkfs`, `chmod 777`, fork bombs, pipe-to-shell, recursive `chown`/`chmod`/`chgrp` on system paths. **Always** blocked, even with an active override.
- **Git safety** — `git reset --hard`, force-push (incl. `--force-with-lease`), `commit --no-verify`, `commit --amend`, `git add -A` / `git add .`, and writing `git config` are **always** blocked. Force-push to `main`/`master` has its own dedicated rule on top.
- **Self-protection** — The AI cannot write the hook, the rules file, the rules document, the active override directory, or the `bin/` scripts — via Bash **or** Write/Edit. No override lifts this. It reaches beyond this repo's own files: the **shell's startup files** (`.zshrc`, `.bashrc`, `.profile`, …) are the ground every command check stands on, and the **control files of other CLIs** (opencode, Antigravity) hand out the same power one directory over.
- **Delete protection** — A second path list for paths that may be *changed* but never *removed*. Write protection would block four maintenance paths to stop one deletion; this separates the two.
- **Glob-aware path matching** — A write target containing `*`, `?` or `[…]` is held against every protected path, component by component: if the pattern *could* hit one, it is refused. Patterns are never expanded — that would make the verdict depend on the filesystem. Without this, `echo x > ~/.claude/setting*.json` walked past the self-protection while the spelled-out name was refused.
- **Container guard** — Container calls are judged by their **subcommand**, not by the tool name: with the tool merely on the sudo allowlist, every subcommand used to be allowed. Reading and building stay free (`ps`, `logs`, `inspect`, `exec`, `run`, `build`, `cp`, `attach`, `pull` …); tearing down (`rm`, `kill`, `stop`, `prune` …) needs a level-1+ override. Escape flags — `--privileged`, `--pid=host`, `--net=host`, `--ipc=host`, `--cap-add=ALL`, mounting the container socket, `seccomp=unconfined` — are refused **hard, with no override**, extendable via `docker.blocked_flags`; so is a bind-mount whose host source overlaps a self-protected path. What runs *inside* a container is a **named boundary, not an oversight**: `exec` is the most frequent form (58.2 % of 107,593 audited calls), its inner command is an interpreter in roughly 70 % of cases, and paths inside a container cannot be judged from the host. Reads are still caught by the read protection, which sees the inner command.
- **Owner-only commands** — The approval and dev-mode scripts are hard-blocked for AI Bash calls, so the AI cannot grant itself rights.
- **Protected paths** — Level-dependent write protection for `~/.ssh`, `~/.gnupg`, `/etc/shadow`, `/boot`, `/usr/bin`, etc.
- **Credential & `.env` read protection** — The Read tool cannot reach private keys, cloud credentials, or `.env` files without a level-1+ override. Public keys and SSH config stay open.
- **3-level, agent-scoped override system** — Scoped, explicit, auditable, and per-instance.
- **Audit log** — Every allow/block decision is logged (JSONL) with secret redaction.
- **Desktop notifications** — Optional heads-up on package installs.
- **Prompt injection detection** — Warns (doesn't block) when suspicious keywords appear in a command.
- **Diagnostics register** — A second hook (`Stop` + `SessionStart`) that records language-server warnings the AI would otherwise file away, and asks for a reason instead of an acknowledgement. Five states; `fixed` is measured, not claimed. See [docs/diagnostics-register.md](docs/diagnostics-register.md).
- **Update check** — Optional, off by default: one line at session start when a newer version has been published. Reads and compares, nothing else.

---

## Before you install: is this for you?

```bash
git clone https://github.com/inoX-Network/claude-code-safety-guard
cd claude-code-safety-guard
python3 tools/would-it-help.py
```

It tells you what it is about to read and waits for your yes; without one it
reads nothing. Nothing is installed, written or sent anywhere. It counts what
is reachable from your machine (keys, remote hosts, credentials — existence
only, no protected file is ever opened), notes which AI assistants with tool
access live there, and then feeds your own past commands to the **real hook in
this checkout** to see how many of them it would have stopped.

Then it tells you, in plain sentences, whether that is worth it — **including
"probably not".** If no assistant with tool access is found, it says the guard
would protect you from nothing today and to come back when that changes. A
report that recommends itself whatever it finds would be worthless, because you
could not tell the honest cases from the sales pitch.

One caveat it prints rather than hides: **the guard protects you from an agent,
not from yourself.** Where an agent's log exists it is used; where only shell
history exists, the report says so and labels its own numbers as the weaker
evidence they are.

### What your assistant is told here

This repository contains [`AGENTS.md`](AGENTS.md) (and `CLAUDE.md`, a pointer to
the same file) — notes that an AI assistant reads when it opens the project.
**They are worth reading yourself**, because you should know what is being said
to something acting on your behalf.

The short version of what they say: this guard sits in front of the assistant's
own tool calls; a refusal is a signal to stop and rephrase, never something to
work around; the assessment above exists and is usually worth offering; do not
oversell its verdict, and do not run it without asking. Nothing in there
instructs an assistant to recommend this project.

That disclosure is deliberate. A file in a repository that issues instructions
to a foreign agent has the same shape as a prompt injection, and a security tool
should not be the one demonstrating it quietly.

If you would rather your assistant did not read it: delete both files. Nothing
about what the guard blocks depends on them — they are addressed to a reader,
not to the hook.

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
- **Delete protection names a path, not its ancestors.** `blocked_paths_delete`
  — and the self-protection of the guard's own files — refuses destroying a
  *named* path and everything under it, but naming an **ancestor directory**
  removes the protected path as a side effect without matching either list.
  Measured: `rm -rf ~/.claude/projects` and `rm -rf ~/.claude/hooks` are refused,
  yet `rm -rf ~/.claude` — which takes both with it — passes, and so do
  `find ~/.claude -delete` and `find ~/.claude | xargs rm`, where the protected
  path never appears as a literal `rm` argument. The intended fix is a
  depth-aware rule: block a *recursive* delete at or near the root of a protected
  tree while single-file deletes underneath stay free, so everyday maintenance is
  untouched. Until then, an OS sandbox / least privilege is the hard boundary —
  as for every row in THREAT-MODEL.md.

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
| `~/.claude/guard-config.json` | this installation's own config — it says **where the rules live**, so whoever can write it points the guard at an empty rule set and disarms it without touching a single rule |

Two further groups belong to the same list and have their own sections below,
because they are longer than a table row: the **shell's startup files**, and
the **control files of other tool chains** (opencode, Antigravity) — including
the project-local ones, which are a rule rather than a list of places.

The list is hardcoded in the hook (not in the JSON rules) on purpose: if it lived in the rules file, the protection list could be edited through itself. The pending directory `~/.claude/.sudo-overrides-pending` is **deliberately not** protected — the AI must be able to drop proposals there.

**A neighbour is not the path.** Every protected entry is matched with a path
boundary, so a directory whose name merely *starts* with a protected one stays
free: `~/.claude/.sudo-overrides-pending` (proposals), a `.zshrc.bak`, a
`hooks-old/`. Without that boundary the prefix match drags them all in.

### The shell rewrites the command after the guard has read it

Self-protection compares paths. The shell *assembles* paths, and it does so
after the hook has already made its decision. Three rewrites are undone up
front, before any check runs:

| Written | What the shell runs | Was it caught before? |
|---|---|---|
| `cat${IFS}~/.ssh/id_rsa` | `cat ~/.ssh/id_rsa` | yes |
| `echo x > ~/.claude/set''tings.json` | `… > ~/.claude/settings.json` | **no** |
| `echo x > ~/.claude/{settings,x}.json` | `… > ~/.claude/settings.json …` | **no** |

The last two reached the file this guard is built to defend above all others —
its own settings — with no tool, no encoding and no override. Measured against
a byte-identical copy of the live hook: the plain spelling was refused, both of
these went through.

**Why these three and not globbing.** All three are *state-free*: the result
depends only on the string, so undoing them ahead of the check is safe. A glob
is not — `~/.claude/setting*.json` resolves against whatever happens to exist,
so expanding it would make the verdict depend on the filesystem and reopen a
time-of-check question. A pattern is therefore held against the protected list
**unexpanded** instead, component by component. Two mechanisms, because the two
problems are genuinely different.

**What it costs.** Nothing measurable: 1.4 µs per command against 0.1 µs
before, on a hook that spends about 30 ms starting a Python process. And
nothing in false alarms — replayed against 215,936 logged commands, exactly two
became newly blocked, and both were this project's own attack probes from the
audit that motivated the change. Zero real commands.

**One exception, found by that measurement rather than by thinking.** A JSON
payload is not a brace list. `PARAMS='{"a":"b","c":"d"}'` looks like one, and
expanding it duplicated the surrounding word — which put a second command name
where a command name is read, and refused a perfectly ordinary line. Brace
lists carrying `"key":` are left alone.

**What this does not close.** The shell also removes *non-empty* quotes and
backslashes, and those spellings still reach a protected path:
`~/.claude/"settings".json` and `~/.claude/set\tings.json` are both allowed
today. They behave identically before and after this change — the next class in
the same family, needing a different answer, because removing them is not
state-free in the same simple way: a quote can span words and a backslash can
escape a separator.

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
[Supported tool chains](docs/tool-chains.md). Its `hooks.json` is the sharp end: the
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
| Commit on a protected branch | `git commit` while the repository is on a branch in `protected_git_branches` (`main` by default) — see the note below |
| Self-protection paths | the hook, rules file, rules doc, active override dir, `bin/` (see above) |
| Owner-only commands | `grant-override`, `hook-dev-mode` (AI Bash calls) |
| Credential reads | `/etc/shadow`, `/etc/gshadow` |

**About committing on `main`.** This one surprises people, so it is worth
saying plainly: with the shipped rules, an AI cannot commit while your
repository sits on `main`. Not the message, not the flags — the branch. The
hook asks git for the real branch (`rev-parse`), so `cd repo && git commit` and
`git -C repo commit` are covered too; merges and pulls stay free, and so does
committing on any other branch. Change `protected_git_branches` if that does
not fit how you work.

It also reaches further than it looks. Running this repository's own test suite
from a clone standing on `main` turns one case red — a case asserting that a
commit message may merely *mention* a blocked command. Nothing is wrong with
the guard there and nothing with the case: the test simply ran somewhere a
second, unrelated rule applies. Both an external reviewer and the suite itself
were caught by that on 2026-08-27, which is why the tests now state their
working directory instead of inheriting it.

---

## Installation settings & language

Two files, two jobs. **`security-rules.json`** says *what* is allowed — every key of it is in [docs/configuration-reference.md](docs/configuration-reference.md). **`~/.claude/guard-config.json`** says where this machine keeps things, and in which language the guard speaks. It is entirely optional: without it the guard runs on its defaults, in English. See [guard-config.example.json](guard-config.example.json).

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
    "source": "https://api.github.com/repos/inoX-Network/claude-code-safety-guard/releases/latest"
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

What it does: compares the `VERSION` file next to the hook against the latest
**release**, and prints one line if that one is newer. What it does not do:
download anything, change anything, or run with elevated rights. It reads,
compares, and speaks.

The published version is read from a release rather than from the tip of
`main`, because "a newer version exists" has to mean something you can go and
look at. `main` moves several times a day; announcing it meant announcing a
state that could already be one merge old — and, on a bad day, one that had
not been through CI.

A version is a date, optionally with a counter: `2026.08.21`, `2026.08.27-2`.
The counter is not decoration. On 2026-08-27 eleven commits landed in one day,
two of which changed what the guard blocks — one before the version was
raised, one after. The second could not be announced, because the date had
nowhere left to move. Counters are compared as numbers, so `-10` is newer
than `-2`.

The notice names [CHANGELOG.md](CHANGELOG.md) instead of characterising what
changed. It used to say the changes were "almost always security fixes", which
the script has no way of knowing: the entry that raised the version on
2026-08-27 was a documentation commit. The changelog marks per entry whether
it closes a way around the guard.

Without a `VERSION` file next to the hook there is nothing to compare, and it
stays silent rather than guessing.

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

## Reference

This README says what the guard does and why. The parts you look things up in
live next to it:

| Document | What is in it |
|---|---|
| [INSTALL.md](INSTALL.md) | the from-scratch setup, step by step |
| [docs/configuration-reference.md](docs/configuration-reference.md) | every key in `security-rules.json` |
| [docs/tool-chains.md](docs/tool-chains.md) | Claude Code, opencode, Antigravity — and how to wire up a fourth |
| [docs/diagnostics-register.md](docs/diagnostics-register.md) | the second hook: language-server warnings that cannot be filed away |
| [THREAT-MODEL.md](THREAT-MODEL.md) | what this deliberately does **not** do |
| [SECURITY.md](SECURITY.md) | how to report a bypass without publishing it first |
| [CHANGELOG.md](CHANGELOG.md) | what changed, and which changes were security fixes |
| [docs/whats-new-in-v2.md](docs/whats-new-in-v2.md) | for returning readers of the first version |
| [docs/counter-tests/](docs/counter-tests/) | reproduction steps for three closed gaps, to check them on your own machine |

---

## Contributing

Issues and PRs welcome. If you've been bitten by a similar incident and have
patterns to add to the blocklist, please share them. Found a way *around* the
guard? [SECURITY.md](SECURITY.md) has a non-public route — please use it.

[CONTRIBUTING.md](CONTRIBUTING.md) has the details. The short version:

```bash
pip install -r requirements-dev.txt
python3 -m pytest tests/ -q
```

The suite needs no installation of the guard itself. Two areas measure more
when `git` and `pyright` are present; without them those cases skip and say so
rather than failing. One case needs a real `~/.claude` and skips otherwise.

See [INSTALL.md](INSTALL.md#e-verify-its-armed) for how to verify a live
installation, or run `python3 tools/verify-install.py`.

## License

[MIT](LICENSE)

---

*Born from a real incident. Built to prevent the next one.*
