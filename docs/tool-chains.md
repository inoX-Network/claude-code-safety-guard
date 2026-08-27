# Supported tool chains

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

# Wiring up another CLI — the integration contract

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

---

[Back to the README](../README.md)
