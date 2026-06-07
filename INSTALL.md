# Installing the Claude Code Safety Guard

This guide takes you from a fresh clone to an **armed** guard. It assumes a
single-user machine where Claude Code reads its configuration from `~/.claude/`.

Read [README.md](README.md) first for *what* the guard does — this document is
purely *how to deploy it*.

> All paths below are the **real** paths the code uses. They are read from the
> constants in `hooks/command-guard.py`, `bin/grant-override`, and
> `bin/hook-dev-mode`. If you change where files live, see
> [section C](#c-changing-paths) — several places must be kept consistent.

---

## A. File placement

Each repo file has exactly one installation target.

| Repo file | Installation target | Notes |
|-----------|---------------------|-------|
| `hooks/command-guard.py` | `~/.claude/hooks/command-guard.py` | The hook itself. Path is referenced from `settings.json`. |
| `security-rules.example.json` | `~/.claude/safety-guard/security-rules.json` | This is the value of the `RULES_PATH` constant in the hook. Copy the example, then **rename to `security-rules.json`** and customize. The `.example.` file is *not* read at runtime. |
| `rules/security-operations.md` | `~/.claude/rules/security-operations.md` | The override protocol, loaded as AI context (see [section B](#b-required-ai-context)). |
| `bin/grant-override` | `~/.claude/bin/grant-override` | Owner-only approval script. `chmod +x` it. |
| `bin/hook-dev-mode` | `~/.claude/bin/hook-dev-mode` | Owner-only dev-mode switch. `chmod +x` it. |
| `settings.example.json` | merge its **6 PreToolUse matchers** into `~/.claude/settings.json` | Do not overwrite your existing settings — merge the `hooks.PreToolUse` array. |

### Runtime directories and files

The hook and scripts also use these locations. The ones marked *auto* are
created automatically on first use (`mkdir(parents=True, exist_ok=True)`); the
rest you create yourself.

| Path | Purpose | Who creates it |
|------|---------|----------------|
| `~/.claude/hooks/` | hook source dir | you (when copying the hook) |
| `~/.claude/safety-guard/` | holds the live `security-rules.json` | you |
| `~/.claude/rules/` | holds `security-operations.md` | you |
| `~/.claude/bin/` | holds the two owner-only scripts | you |
| `~/.claude/.sudo-overrides/` | **active** override files the hook reads | created by `grant-override`; safe to `mkdir` early |
| `~/.claude/.sudo-overrides-pending/` | proposals the AI writes (`confirmed: false`) | you should `mkdir` it so the AI has somewhere to drop proposals |
| `~/.claude/.agent-audit/` | `actions.jsonl` audit log | *auto* |
| `~/.claude/.hook-dev-mode` | dev-mode flag file (JSON) | created/removed by `hook-dev-mode on`/`off` |

### Step-by-step

```bash
# 1. Directories
mkdir -p ~/.claude/hooks
mkdir -p ~/.claude/safety-guard
mkdir -p ~/.claude/rules
mkdir -p ~/.claude/bin
mkdir -p ~/.claude/.sudo-overrides
mkdir -p ~/.claude/.sudo-overrides-pending

# 2. The hook
cp hooks/command-guard.py ~/.claude/hooks/command-guard.py

# 3. The rules file — note the rename from .example.json to .json
cp security-rules.example.json ~/.claude/safety-guard/security-rules.json

# 4. The rules document (AI context)
cp rules/security-operations.md ~/.claude/rules/security-operations.md

# 5. The owner-only scripts — make them executable
cp bin/grant-override ~/.claude/bin/grant-override
cp bin/hook-dev-mode ~/.claude/bin/hook-dev-mode
chmod +x ~/.claude/bin/grant-override ~/.claude/bin/hook-dev-mode
```

> The two scripts are invoked by the owner via `!` (which bypasses the guard).
> If `~/.claude/bin` is not on your `PATH`, always call them with the full path,
> exactly as the guard's block messages and the rules document show:
> `! ~/.claude/bin/grant-override …`

### 6. Wire up the hook in `settings.json`

`settings.example.json` defines **six** PreToolUse matchers — one each for
`Bash`, `Read`, `Write`, `Edit`, `MultiEdit`, and `NotebookEdit`, all pointing
at the same hook:

```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "Bash",         "hooks": [{ "type": "command", "command": "python3 ~/.claude/hooks/command-guard.py" }] },
      { "matcher": "Read",         "hooks": [{ "type": "command", "command": "python3 ~/.claude/hooks/command-guard.py" }] },
      { "matcher": "Write",        "hooks": [{ "type": "command", "command": "python3 ~/.claude/hooks/command-guard.py" }] },
      { "matcher": "Edit",         "hooks": [{ "type": "command", "command": "python3 ~/.claude/hooks/command-guard.py" }] },
      { "matcher": "MultiEdit",    "hooks": [{ "type": "command", "command": "python3 ~/.claude/hooks/command-guard.py" }] },
      { "matcher": "NotebookEdit", "hooks": [{ "type": "command", "command": "python3 ~/.claude/hooks/command-guard.py" }] }
    ]
  }
}
```

Merge these into your existing `~/.claude/settings.json` (see the full file in
[settings.example.json](settings.example.json)). Restart your Claude Code
session so the new hook configuration is picked up.

> All six matchers run the **same** script. The hook decides what to check based
> on the `tool_name` it reads from stdin, so you do not need separate scripts.

---

## B. Required AI context (memory / CLAUDE.md)

The guard works without any AI context — it enforces purely from the hook. But
for the AI to *operate the system correctly* (understand a block message,
**propose** an override instead of trying to grant itself one, and respect the
self-protection), it needs the override protocol as context.

Two ways to provide it:

1. **Drop `rules/security-operations.md` into `~/.claude/rules/`** (done in
   section A). Files in `~/.claude/rules/` are loaded as context.
2. **Reference it from a `CLAUDE.md`.** If you keep a project or global
   `CLAUDE.md`, add a short block that points at the rules document and
   summarizes the contract.

A minimal, generic `CLAUDE.md` block:

```markdown
## Safety guard is armed

A PreToolUse hook (`command-guard.py`) enforces the security rules technically
for Bash, Read, Write, Edit, MultiEdit, and NotebookEdit. The hook and its
override files are the authority — not this prompt. You cannot grant yourself
any rights.

When an action is (or will be) blocked and you genuinely need it:
1. Determine the lowest sufficient level (1/2/3) and the minimal scope.
2. Write an override PROPOSAL (with `confirmed: false`) into
   `~/.claude/.sudo-overrides-pending/`. You may write there; the active
   override directory is self-protected and you cannot.
3. Hand the owner a ready-to-copy command and explain level + scope:
   `! ~/.claude/bin/grant-override <id> --minutes N [--confirm LABEL] [--snapshot ID]`
4. Only the owner's `!` invocation activates the override. The hook then grants
   the scope until it expires.

You can never write the hook, the rules file, the rules document, the active
override directory, or the `bin/` scripts. No override lifts that.

Full protocol: `~/.claude/rules/security-operations.md`.
```

Keep this block generic — no machine-specific names, IPs, or paths beyond the
`~/.claude/` ones above.

---

## C. Changing paths

If you want the files somewhere other than the defaults, change them in **all**
the places below — otherwise the guard either won't find its rules or, worse,
won't protect itself.

### Constants in `hooks/command-guard.py`

| Constant | Default | What it controls |
|----------|---------|------------------|
| `RULES_PATH` | `~/.claude/safety-guard/security-rules.json` | Where the hook loads the live rules. If missing, the hook warns and applies **no** Bash rules (fail-closed). |
| `SELF_PROTECT_PATHS` | the list in the README | Paths the AI can never write. **If you move the hook, the rules file, or the override/bin dirs, you must update this list to match** — otherwise the guard no longer protects its own files. |
| `DEV_UNLOCKABLE_PATHS` | `~/.claude/hooks`, `~/.claude/safety-guard/security-rules.json` | The only paths dev mode can temporarily unlock. Keep in sync with where the hook + rules live. |
| `HOOK_DEV_FLAG` | `~/.claude/.hook-dev-mode` | The dev-mode flag file (also a self-protect path). |

> **Critical:** `RULES_PATH` and the matching entry in `SELF_PROTECT_PATHS`
> (`~/.claude/safety-guard/security-rules.json`) must point at the same file. If
> they drift apart, the AI could write the very rules file the hook reads.

### Environment variables (for tests / relocation)

The hook and scripts honor these env vars; without them the production defaults
apply. They exist mainly for self-tests, but they also relocate the runtime
dirs consistently across the hook and both scripts:

| Env var | Read by | Overrides |
|---------|---------|-----------|
| `CLAUDE_SECURITY_RULES` | hook | path to the live rules file (`RULES_PATH`) |
| `CLAUDE_SUDO_OVERRIDES_DIR` | hook, `grant-override` | active override directory |
| `CLAUDE_SUDO_PENDING_DIR` | `grant-override` | pending proposals directory |
| `CLAUDE_AUDIT_DIR` | hook, `grant-override`, `hook-dev-mode` | audit log directory |
| `CLAUDE_HOOK_DEV_FLAG` | hook, `hook-dev-mode` | dev-mode flag file |

> The test suite uses `CLAUDE_SECURITY_RULES` to point the hook at
> `security-rules.example.json` and the `CLAUDE_*_DIR` vars to isolate runtime
> state in a temp directory, so the tests never touch your real `~/.claude`.

### `settings.json`

The `command` of each matcher (`python3 ~/.claude/hooks/command-guard.py`) is a
literal path. If you move the hook, update all six matchers.

### Script-internal paths

`bin/grant-override` and `bin/hook-dev-mode` build their default paths from
`Path.home() / ".claude" / …` (override dir, pending dir, audit dir, flag file).
If you relocate those directories permanently, set the env vars above in the
environment the owner runs the scripts in, or edit the path constants at the top
of each script.

---

## D. `.gitignore`

The repo already ships a [`.gitignore`](.gitignore). It exists to keep your
machine-specific and runtime artifacts out of any clone you push. **Never
commit:**

- `security-rules.json` — your real, machine-specific rules (only the
  `*.example.json` belongs in the repo).
- `.sudo-overrides/`, `.sudo-overrides-pending/`, `.sudo-overrides-archiv/` —
  override files (they contain task descriptions, agent ids, timestamps).
- `.agent-audit/` and `actions.jsonl` — the audit log.
- `.hook-dev-mode` — the dev-mode flag.
- `session-state.json` — local Claude Code session state.

If you keep your real `~/.claude/` under version control, make sure these same
patterns are ignored there too.

---

## E. Verify it's armed

### Run the automated test suite

The repo ships its own tests. They are self-contained: they point the hook at
`security-rules.example.json` and isolate all runtime state (overrides, audit
log, dev-mode flag) in a temp directory via environment variables, so they
**never touch your real `~/.claude`**. Run them straight from the clone, before
or after installing — only Python 3 is required:

```bash
python3 tests/test_command_guard.py    # hook behavior — 76 cases
python3 tests/test_freigabe_e2e.py     # approval channel + dev mode — 25 cases
```

Expected output ends with `76 passed, 0 failed` and `25 passed, 0 failed`. Each
case feeds the real hook a constructed stdin payload and asserts its exit code
(`0` = allow, `2` = block), so a green run means the guard in this checkout
enforces exactly what it should.

### Manually verify it's armed in Claude Code

After installing and restarting your session, confirm the guard actually blocks.
Ask the AI (not yourself via `!`, which bypasses the guard) to attempt each:

1. **Self-protection blocks a write to the hook.**
   Ask the AI to write or append to `~/.claude/hooks/command-guard.py`.
   → Expect **BLOCKED** (`self_protect`). No override should change this.

2. **Owner-only command is blocked from AI Bash.**
   Ask the AI to run `~/.claude/bin/grant-override` in a Bash command.
   → Expect **BLOCKED** (`owner_only`). Only an owner `!` invocation may run it.

3. **A harmless write is allowed.**
   Ask the AI to write a file under `/tmp` (e.g. `/tmp/guard-test.txt`).
   → Expect **allowed**.

4. **A protected read needs an override.**
   Ask the AI to read a `.env` file or `~/.ssh/id_*`.
   → Expect **BLOCKED** with a "requires override level 1+" message.

5. **An always-blocked pattern is refused.**
   Ask the AI to run something matching a blocked pattern (e.g. a recursive
   `chown` on `/etc`).
   → Expect **BLOCKED** (`blocked_pattern`) regardless of any override.

You can also tail the audit log to watch decisions land:

```bash
tail -f ~/.claude/.agent-audit/actions.jsonl
```

Each line records `tool`, `target` (secret-redacted), `decision`, `reason`, and
`level`. If you see `allow`/`block` lines appear as you test, the hook is wired
in correctly.
