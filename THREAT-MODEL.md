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
- **Interpreter inline code** — `python -c`, `node -e`, `ruby -e`, `perl -e`,
  `php -r` etc. that read a protected path embedded inside the code, or write
  to a self-protected file. Scanned by substring against the same tier logic,
  so obfuscation via interpreters does not bypass the credential/self-protect
  gates.
- **Shell word-split obfuscation** — `${IFS}`/`$IFS` are normalised to
  whitespace before every check, so `cat${IFS}~/.ssh/id_rsa` is caught.
- **Protected-path writes** — Bash and `Write`/`Edit`/`MultiEdit`/`NotebookEdit`
  against `~/.ssh`, `/etc/*`, `/boot`, `/usr/bin`, etc. Level-dependent.
- **Self-protection** — no tool call (Bash or editor, including interpreter
  one-liners) may modify the guard itself: its hook, rules, override directory,
  approval scripts, settings, or rules docs. No override lifts this; only the
  owner via `!` (or scoped dev mode for the hook sources).
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
