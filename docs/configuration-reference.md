# Configuration reference

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
| `docker.blocked_flags` | `string[]` | Extra container flags to refuse, **added to** a built-in list (`--privileged`, `--pid=host`, `--net=host`, `--ipc=host`, `--uts=host`, `--cap-add=ALL`, `--cap-add=SYS_ADMIN`, the container socket, `seccomp=unconfined`, `apparmor=unconfined`). Matched case-insensitively, since the container tool treats `--cap-add=all` and `=ALL` alike. The built-in list cannot be shortened from the rules file. |
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

---

[Back to the README](../README.md)
