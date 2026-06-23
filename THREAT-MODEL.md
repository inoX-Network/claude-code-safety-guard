# Threat Model & Scope

This guard does **one job well**: it is a deterministic, fast, auditable
`PreToolUse` backstop that blocks known-catastrophic and credential-exposing
operations *as they pass through Claude Code's tool calls* — for the case where
the model's own judgment (or the permission prompt) fails or is subverted by
prompt injection.

It is **not** a sandbox, not a malware scanner, and not a substitute for
running the agent with least privilege. Security comes from layering. This
document states honestly what the hook does, what it deliberately does **not**
do, and which layer is responsible for the rest.

## What the hook catches (in scope)

- **Catastrophic patterns** — `rm -rf /`, `mkfs`, `chmod 777`, fork bombs,
  pipe-to-shell, recursive `chown`/`chmod`/`chgrp` on system paths. Always
  blocked, no override.
- **Force-push & destructive git** — `git push --force` to `main`/`master` and
  configured git-safety violations. Always blocked.
- **Credential reads** — Read tool *and* Bash-side (`cat`, `base64`, `cp`,
  `dd if=`, `tar`/`zip`/`rsync` of key directories) against private keys,
  cloud credentials, `.npmrc`, Docker/GnuPG config, `.env` files. Override
  level 1+ required; `/etc/shadow` always blocked.
- **Interpreter inline code (literal embedding)** — `python -c`, `node -e`,
  `ruby -e`, `perl -e`, `php -r` etc. that read a protected path written
  **literally** inside the code, or write to a self-protected file. Path-like
  literals are matched against the same tier logic, so the naive case
  (`open("~/.ssh/id_rsa")`) is caught. This closes the literal vector **only** —
  string-building (`open("~/.ss"+"h/id_rsa")`), base64, or `$(…)` staging produce
  no literal for the hook to see, and belong to the same boundary as
  "Obfuscation in general" below (sandbox / least privilege).
- **Shell word-split obfuscation** — `${IFS}`/`$IFS` are normalised to
  whitespace before every check, so `cat${IFS}~/.ssh/id_rsa` is caught.
- **Protected-path writes** — Bash and `Write`/`Edit`/`MultiEdit`/`NotebookEdit`
  against `~/.ssh`, `/etc/*`, `/boot`, `/usr/bin`, etc. Level-dependent.
- **Docker / Podman host access** — catastrophic flags (`--privileged`, the
  Docker socket, host namespaces `--pid/network/ipc/uts=host`,
  `--cap-add=ALL/SYS_ADMIN`, `seccomp/apparmor=unconfined`) are always blocked.
  A bind-mount whose host source *is, contains, or lies under* a self-protected
  path is always blocked (**encirclement** — a container editing the guard's own
  files from the inside, which on the host never appears as an `Edit`/`>`). A
  bind-mount onto another protected write-path (`/etc`, `~/.ssh`, …) is
  level-dependent, exactly like a direct write. Normal container work
  (`docker run -v ./project:/app …`, named volumes, `$(pwd)`) runs free. One
  check on the Bash command string — so opencode inherits it (Docker arrives via
  `bash`, not the un-gated `apply_patch`, so the opencode caveat below does not
  weaken it).
- **Self-protection (Claude Code)** — under Claude Code, no tool call (Bash or
  editor, including interpreter one-liners) may modify the guard itself: its
  hook, rules, override directory, approval scripts, settings, or rules docs. No
  override lifts this; only the owner via `!`. The one relaxation is **dev mode**
  — the single owner-only window in which hook-*source* self-protection is
  deliberately lowered (and only the hook sources; settings, the override dir and
  `bin/` stay hard-protected even then). It is therefore the most sensitive
  surface of the whole system: **never enable dev mode on an unattended or remote
  session.** (Under opencode this guarantee does not hold deterministically — see
  the limits table below.)
- **MCP tool calls** — default-deny for write/unknown MCP tools; read verbs and
  whitelisted safe servers pass; sensitive servers gated at level 1+.
- **Sudo** — only whitelisted commands follow `sudo`; tab/whitespace bypasses
  closed.
- **Fail-closed** — if the rules file is missing, unreadable, or empty, a
  hardcoded minimal ruleset takes over instead of allowing everything.

## What the hook does NOT catch (out of scope — by design)

These are **not** failures of the hook. They belong to a different layer, and
trying to handle them here would only add false positives and false confidence.

| Gap | Why the hook can't / shouldn't | Where it actually belongs |
|---|---|---|
| **The agent runs as you.** Any read/write your own user may do in your own `$HOME`, the hook can only pattern-match, never truly prevent. | `sudo` and the hook both operate inside your user context. A wall, not a pattern, is needed. | **OS sandbox / least privilege** — run Claude Code in its native sandbox, a container, firejail/bubblewrap, or as a dedicated low-privilege user. |
| **Deferred execution.** Malicious content written into `Makefile`, `package.json` (`postinstall`), `.bashrc`, build configs — fires *later*, when a normal command (`make`, `npm install`) runs. | These files are written constantly in normal work. The malicious entry is byte-for-byte indistinguishable from a legitimate one. Gating them = false positives on nearly every project → users disable the guard. | **Package manager & discipline** — `npm install --ignore-scripts`, lockfile review, pinned/audited dependencies. (Scheduler-based persistence — `cron`, `at`, `systemd` timers, `.git/hooks`, autostart — *is* in scope as an optional gate, because it is rare and distinctive.) |
| **"Is this content malicious?"** Judging whether a script/diff/file is hostile. | A deterministic hook cannot reason about intent. An LLM classifier inside the hook would be non-deterministic, slow on every call, and itself injectable by the very content it inspects. | **Advisory review layer** — a separate, non-blocking LLM-in-the-loop review (fresh context) plus a human who gates. Advisor, not gatekeeper. |
| **Obfuscation in general.** Bash is Turing-complete; a determined attacker can encode payloads through user-defined variables, indirect expansion, or external stages the hook never sees as a literal string. | No regex/substring layer can fully tame a Turing-complete shell. The hook closes the common, high-signal vectors, not every theoretical one. | **Sandbox + least privilege** as the hard boundary; the hook as defense-in-depth on top. |
| **opencode write/self-protect gates are not deterministic.** Under opencode (vs. Claude Code) the guard runs as a plugin bridge. `apply_patch` is **not** gated — it carries a multi-file `patchText`, not a single path — so it is an un-gated write path, including to self-protected files. The bridge also forwards `session_id` only optionally and never `agent_id`. | A multi-file patch cannot map onto the file-path-based write/self-protect checks, and the bridge cannot supply the `agent_id`/stable `session_id` scoping the hook expects. So the "no tool call may modify the guard" and protected-path-write guarantees above hold for Claude Code, **not** deterministically for opencode. | **opencode's native `permission`** — set `apply_patch`/`edit` to `ask`/`deny` in `opencode.json` as a conscious config — plus sandbox/least-privilege. For session-bound overrides use `--all-sessions` (see SESSION-BINDING-GAP.md §7). |
| **Docker ≈ host-root; indirect & obfuscated container starts.** If the agent's user is in the `docker` group, the daemon can be driven to root regardless of any flag-gating. `docker compose up` (flags live in YAML), Makefile targets and shell scripts never expose the flags as a literal; `-v $(echo /):/host` hides the mount source; `docker exec` into an already-running container is not gated; `--device` is likewise not gated (a raw block device such as `/dev/sda` would be a vector, but `--device` is also legitimate — GPUs, `/dev/dri` — so a blanket block would break normal workflows). Lexical traversal in mount sources (`-v /etc/../etc`, `//etc`) *is* normalised and caught. | The Docker check reduces the surface of *direct, literal, flagged* `docker run`/`cp` calls through the tool path — it is **not** daemon-level access control, and the same Turing-complete / deferred-execution limits as the rows above apply to indirect starts and substituted sources. Container *creation* is gated (A/B), so a dangerous container is hard to create directly; `docker exec` is mitigated by that. (Root-owned files a root container leaves behind are a usability annoyance, not a hole.) | **Rootless Docker, a dedicated build user, or no daemon access** — plus sandbox/least-privilege. Gate flags in `compose`/Makefiles at their source. |

## How it composes

```
┌─────────────────────────────────────────────┐
│ OS sandbox / least privilege  (the WALL)     │  <- agent physically cannot reach what's outside
│  ┌─────────────────────────────────────────┐ │
│  │ Claude Code permissions  (the DOOR)      │ │
│  │  ┌──────────────────────────────────────┐│ │
│  │  │ THIS HOOK  (the BOUNCER w/ clipboard) ││ │  <- deterministic, scoped, auditable
│  │  └──────────────────────────────────────┘│ │
│  └─────────────────────────────────────────┘ │
└─────────────────────────────────────────────┘
   + advisory LLM review (the AUDITOR) — non-blocking, human gates
```

The hook is the bouncer **inside** the wall: fine-grained, override-aware,
logged. It assumes the wall (sandbox) and the door (permissions) exist and does
not try to replace them. Remove the wall and the bouncer still helps — but he
was never meant to be the building's only defense.

## Design principles (why the scope stays narrow)

1. **Deterministic** — same input, same verdict, every time. Testable
   (see the test suite), auditable, reproducible. No dice rolls.
2. **Fast** — runs on every tool call; must not add network round-trips or
   model latency.
3. **Independent of the LLM** — it is the net for when the model's judgment
   fails, so it must not itself depend on a model's judgment.
4. **Honest about limits** — a tool that claims to stop everything gets taken
   apart. A tool that does *exactly one thing well* and documents the rest
   earns trust.
