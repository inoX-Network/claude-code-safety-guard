# Counter-Test: Override Scope Across Parallel Main Sessions

This document describes the closed gap and provides reproducible test cases for
**counter-testing on a local machine** (Claude Code with the `command-guard.py`
hook active).

- **Branch:** `feature/0050-session-binding`
- **Changed files:** `hooks/command-guard.py`, `tests/test_command_guard.py`, `SESSION-BINDING-GAP.md`
- **Expected hook behaviour:** exit `0` = allowed, exit `2` = blocked

---

## 1. What is this about?

Overrides are scoped by `agent_id`: a main session uses agent-free override files,
a subagent uses `agent-<id>.json` and does **not** inherit the coordinator's
override. That covers the coordinator → subagent direction.

What it did **not** cover: **multiple parallel main sessions.** Several Claude Code
instances (e.g. two terminals, or an external IDE that spawns its own agent process)
all present to the guard as `agent_id = None` — i.e. all of them are "the main
session". An override you grant for *one* of them therefore applies to **all** of
them within its time window.

This is not hypothetical — it surfaced from a real setup. IDEs built **on top of
the Claude Code CLI** inherit this `PreToolUse` hook automatically: the guard fires
straight from `~/.claude/settings.json`, no plugin or porting needed. A visual
workspace like [Nimbalyst](https://github.com/Nimbalyst/nimbalyst) runs Claude Code
under the hood and orchestrates **several agents in parallel, each as its own
session** — and every one of them reaches the guard as `agent_id = None`. Without
session scoping, a single deploy override granted in one agent's session would
silently apply to every other parallel agent during its window. That multi-session
case is what motivated the optional `session_id` binding below.

### Before (the gap)

| Situation | Behaviour | correct? |
|---|---|---|
| Grant deploy override in session A | session A may use it | ✅ |
| A second parallel session B (`agent_id=None`) | **also** may use it | ❌ not what you authorised |

This matters once anything else runs as a parallel main session — a second IDE
window, a wrapper tool, or a prompt-injected agent — during the override window.

---

## 2. The fix (optional session_id binding)

`load_override(agent_id=None, session_id=None)` gains a session check in
`_matches_context`. An override file MAY carry a `session_id` field:

- with `session_id` → the override applies **only** when the current call's
  `session_id` matches,
- without `session_id` → applies across sessions, exactly as before
  (**backward-compatible**).

The `agent_id` scoping is unchanged and orthogonal — both conditions must hold.
The hook already reads `session_id` from the stdin payload (used for the audit
log), so no new input is required; the value is threaded to every `load_override`
call site.

```python
def _matches_context(data: dict) -> bool:
    file_agent = data.get("agent_id")
    if agent_id is None:
        if file_agent is not None:
            return False
    else:
        if file_agent != agent_id:
            return False
    file_session = data.get("session_id")
    if file_session is not None and file_session != session_id:
        return False
    return True
```

Fail-closed: if the override carries a `session_id` but the call has none (or a
different one), the override does not apply.

---

## 3. Test cases (no override / bound override)

| Override | Call session | Result |
|---|---|---|
| L1 grant `htop`, bound to `S1` | `S1` | `sudo htop` allowed |
| L1 grant `htop`, bound to `S1` | `S2` | `sudo htop` **blocked** |
| L1 grant `htop`, **no** `session_id` | any | `sudo htop` allowed (compat) |
| L1 `allowed_paths=/etc/fstab`, bound `S1` | `S1` | write allowed |
| L1 `allowed_paths=/etc/fstab`, bound `S1` | `S2` | write **blocked** |

## 4. How to test manually

```bash
cd <repo>
export CLAUDE_SECURITY_RULES="$PWD/security-rules.example.json"
D=$(mktemp -d); export CLAUDE_SUDO_OVERRIDES_DIR="$D"
EXP=$(python3 -c "from datetime import *;print((datetime.now(timezone.utc)+timedelta(hours=1)).isoformat())")
cat > "$D/system-x.json" <<EOF
{"override_level":1,"label":"EXTENDED","task":"t","confirmed":true,
 "expires_at":"$EXP","session_id":"S1",
 "grants":{"additional_sudo":["htop"],"allowed_paths":[],"system_paths":false}}
EOF

call(){ printf '%s' "$2" | python3 hooks/command-guard.py >/tmp/g.err 2>&1 && echo "[$1] ALLOWED" || echo "[$1] BLOCKED"; }
call "S1 (match)"  '{"tool_name":"Bash","tool_input":{"command":"sudo htop"},"session_id":"S1"}'
call "S2 (other)"  '{"tool_name":"Bash","tool_input":{"command":"sudo htop"},"session_id":"S2"}'
```

## 5. Automated suite

```bash
python3 tests/test_command_guard.py   # expected: 129 passed, 0 failed
```

The new cases live in the `SESSION_CASES` and `MCP_SESSION_CASES` lists in
`tests/test_command_guard.py`.

---

## 6. Integration with the MCP-policy change

The MCP-tool-policy change (PR #3) is already in `main`. This branch merges `main`
and threads `session_id` through `check_mcp_policy` as well, so MCP write tools are
session-bound too (covered by `MCP_SESSION_CASES`). The test harness was hardened
in the same step: `run_hook` no longer inherits the real `~/.claude/.hook-dev-mode`,
which previously turned self-protect tests falsely red under an active dev mode.

## 7. Known limits

- The binding is only as good as the `session_id` the host passes in the payload.
- It does not replace `agent_id` scoping; it complements it for the parallel
  main-session case.
- An override without `session_id` remains valid across sessions by design — use
  the field when you want to pin an override to one session.
