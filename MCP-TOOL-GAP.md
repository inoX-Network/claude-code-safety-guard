# Counter-Test: Unguarded MCP Tool Calls (github writes, postgres, ...)

This document describes the closed gap and provides reproducible test cases
for **counter-testing on a local machine** (Claude Code with the
`command-guard.py` hook active).

- **Branch:** `feature/0050-mcp-tool-policy`
- **Changed files:** `hooks/command-guard.py`, `security-rules.example.json`, `tests/test_command_guard.py`, `MCP-TOOL-GAP.md`
- **Expected hook behaviour:** exit `0` = allowed, exit `2` = blocked

---

## 1. What is this about?

The hook protected `Bash`, `Read`, `Write`, `Edit`, `MultiEdit` and
`NotebookEdit`. **MCP tool calls were not hooked at all.** A tool named
`mcp__<server>__<tool>` (e.g. from a github or postgres MCP server) ran
completely past the guard — `main()` fell through to `if tool_name != "Bash":
sys.exit(0)` and allowed it.

This matters because MCP servers frequently carry **write** capabilities with
real, hard-to-reverse impact:

- a `github` MCP server can `create_or_update_file`, `push_files`,
  `merge_pull_request` — i.e. write to your source of truth,
- a `postgres` MCP server can run arbitrary SQL.

The protection level was orthogonal to read/write: the gap was **"Bash/file
tool" (guarded) vs. "MCP tool" (unguarded)**, not "read vs. write". A read
looked safe only by accident.

### Before (the gap)

| Tool call | Behaviour | correct? |
|---|---|---|
| `mcp__github__get_file_contents` | ALLOWED | ✅ (read) |
| `mcp__github__create_or_update_file` | **ALLOWED** | ❌ writes to repo |
| `mcp__github__push_files` | **ALLOWED** | ❌ |
| `mcp__postgres__query` | **ALLOWED** | ❌ arbitrary SQL |

**Root cause:** no PreToolUse matcher for `mcp__.*` in `settings.json`, and
`main()` had no branch for `mcp__*` tool names.

---

## 2. The fix (default-deny for writes, read-tolerant)

Two parts:

1. **`settings.json`** gets a PreToolUse matcher `mcp__.*` pointing at
   `command-guard.py`, so MCP calls reach the hook at all.
2. **`command-guard.py`** gains `check_mcp_policy()` and an `mcp__`-branch in
   `main()` (before the `if tool_name != "Bash"` fall-through). The policy
   lives in `security-rules.json` under `mcp_policy`:

```json
"mcp_policy": {
  "gate_servers": ["postgres"],
  "safe_servers": ["context7", "sequential-thinking"],
  "read_verb_prefixes": ["get","list","search","read","view","status","preview","describe","fetch"]
}
```

Decision order for `mcp__<server>__<tool>`:

1. `server` in `gate_servers` → **override level 1+** (e.g. `postgres`: a
   `query` can read *or* write/`DROP`; not decidable by name).
2. `server` in `safe_servers` → **allowed** (local/harmless, any tool).
3. tool verb starts with a `read_verb_prefix` → **allowed** (read-only).
4. otherwise (write verb **or unknown server**) → **override level 1+**.

Step 4 is the default-deny: an unknown future MCP server's write tools are
gated automatically until classified. Override level 1+ lifts cases 1 and 4 —
the same gate already used for `allowed_paths` and `.env` write protection.

If `mcp_policy` is entirely absent (older `security-rules.json`), the hook
passes MCP calls through, so an out-of-sync deployment does not unexpectedly
break existing workflows. The policy IS the protection.

---

## 3. Test cases — must BLOCK (exit 2, no override)

```
mcp__github__create_or_update_file    # write to repo
mcp__github__push_files
mcp__github__merge_pull_request
mcp__postgres__query                  # gate_server: always gated
mcp__postgres__list_schemas           # gate_server: gated even though "list"
mcp__deploy__push_release             # unknown server + write verb -> default-deny
```

## 4. Test cases — must stay ALLOWED (exit 0)

```
mcp__github__get_file_contents        # read verb
mcp__github__list_commits
mcp__github__search_repositories
mcp__context7__query-docs             # safe_server
mcp__deploy__get_status               # unknown server, read verb
```

## 5. Override behaviour (consistent with path/sudo gates)

- With an active **level 1+** override (main session) → `create_or_update_file`
  is **allowed**.
- Subagents do **not inherit**: coordinator override level 1 + an MCP write
  from a subagent (`agent_id` set) → stays **blocked**. An agent-bound override
  (`agent-<id>.json`, level 1+) allows it for that agent only.

## 6. Block message (aligned with the path/sudo blocks)

```
BLOCKED: MCP tool 'mcp__github__create_or_update_file' (writing or not
classified as read-only) requires override level 1+. main session has no valid
override (level 0). ESCALATION: the agent asks the coordinator -> the
coordinator decides with the owner about adjusting the override file.
```

---

## 7. How to test manually

```bash
cd <repo>
export CLAUDE_SECURITY_RULES="$PWD/security-rules.example.json"
unset CLAUDE_SUDO_OVERRIDES_DIR   # = no override active (level 0)

check() {
  echo -n "[$1] "
  printf '%s' "$2" | python3 hooks/command-guard.py >/tmp/guard.err 2>&1 \
    && echo "ALLOWED" || echo "BLOCKED ($(cat /tmp/guard.err))"
}

# must BLOCK:
check "gh create" '{"tool_name":"mcp__github__create_or_update_file","tool_input":{}}'
check "gh push"   '{"tool_name":"mcp__github__push_files","tool_input":{}}'
check "pg query"  '{"tool_name":"mcp__postgres__query","tool_input":{}}'

# must stay ALLOWED:
check "gh get"    '{"tool_name":"mcp__github__get_file_contents","tool_input":{}}'
check "ctx docs"  '{"tool_name":"mcp__context7__query-docs","tool_input":{}}'
```

## 8. Automated suite

```bash
python3 tests/test_command_guard.py   # expected: 122 passed, 0 failed
python3 tests/test_freigabe_e2e.py    # expected:  25 passed, 0 failed
```

The new cases live in the `MCP_CASES` list in `tests/test_command_guard.py`.

---

## 9. Known limits (honestly documented)

- The classification is by **server name** and **tool-name verb prefix**, not
  by inspecting `tool_input`. A write tool whose name happens to start with a
  read verb (e.g. a hypothetical `get_and_delete`) would be mis-allowed; a read
  tool on a `gate_server` is gated for safety. `read_verb_prefixes`,
  `gate_servers` and `safe_servers` are the tuning knobs.
- `gate_servers` is the safe choice for anything where the tool name does not
  reveal the read/write nature (databases, shells, deploy tooling).
- This is defense-in-depth at the tool-dispatch layer. It does not constrain
  what a server does internally once a call is allowed.
