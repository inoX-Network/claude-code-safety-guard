# What's new in v2

If you used the earlier version, here is what changed:

- **Every tool matcher instead of two.** The hook is registered for the write tools and `Read` as well, not just `Bash` — the exact list is in [`settings.example.json`](settings.example.json), which is the only place it is maintained. The write tools are checked against protected paths **and** self-protection — they were previously a blind spot. `tools/verify-install.py` reports any tool your installation leaves unguarded.
- **Real level differentiation.** The hook now evaluates `override_level` 0/1/2/3 individually. It is no longer "any override active → everything allowed". Paths and sudo are unlocked *per level*.
- **Agent scoping.** Subagents do **not** inherit the coordinator's or main session's override. Each agent needs its own override file bound to its `agent_id`, or it runs at level 0.
- **Self-protection.** The hook, the rules file, the rules document, the active override directory and the `bin/` scripts can never be written by the AI — no override lifts this.
- **Approval channel.** The AI can no longer write itself an override. It writes a *proposal*; only the owner activates it via an owner-exclusive script invoked through `!`.
- **Dev mode.** A supervised, time-boxed way for the owner to let the AI edit the hook *sources* — without opening up settings, the override dir, or the rules.
- **Fail-closed (breaking change).** When the rules file or input is missing/unparsable, the hook now behaves **conservatively** (blocks / discards the override) instead of allowing through.
- **Audit log.** Every decision is written to a JSONL audit log with secret redaction.
- **`expires_at` timestamps.** Overrides now end on an ISO-8601 expiry (or when the owner removes the file). The old "the instance deletes its own file" model is gone — the AI cannot delete active override files.

---

---

[Back to the README](../README.md)
