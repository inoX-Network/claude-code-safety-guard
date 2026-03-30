Thanks for the suggestion! The regex approach is solid for catching the
immediate pattern.

After this incident happened to me (I'm the OP), I built a more
comprehensive solution that goes beyond pattern matching:

**[claude-code-safety-guard](https://github.com/inoX-Network/claude-code-safety-guard)** —
A 3-level override system for Claude Code

What it adds beyond the regex approach:

- **External rules file** (security-rules.json) — modify rules without
  touching the hook. Blocked patterns, protected paths, sudo whitelist,
  prompt injection keywords — all configurable.

- **3-level override system** — because sometimes you *need*
  `chown -R` (disaster recovery). Instead of being permanently locked
  out, the operator grants a scoped override:
  - **Level 1 (Extended):** Docker, compose, single-file ops
  - **Level 2 (Full):** All sudo, but recursive on system paths still blocked
  - **Level 3 (Critical):** Emergency only, requires snapshot confirmation,
    double confirmation, no background agents

  Each level requires explicit confirmation with the level number in
  the response. "just do it" doesn't work — you have to say "Level 1 approved".

- **Per-instance override files** — multiple Claude Code sessions can
  run in parallel, each with their own scoped override that only affects
  that session.

- **Blocked patterns always active** — even at Level 3,
  `rm -rf /`, `mkfs`, and `chmod 777` are permanently blocked.
  No override can unlock these.

- **Prompt injection detection** — warns on suspicious keywords in
  commands (doesn't block, but logs).

The hook integrates via PreToolUse in settings.json and works alongside
the built-in permission system.

Born directly from the incident described in this issue. Hope it helps
others avoid the same 5-hour recovery session.
