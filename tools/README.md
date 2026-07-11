# guard-audit

Analysis tool for the command-guard audit log (`~/.claude/.agent-audit/actions.jsonl`).
Read-only, standard library only, no access to protected directories.

Three views from a single source:

- **Override report** — which overrides were granted when, for which task.
- **Block report** — which actions the guard blocked and why, aggregated by
  reason category (`protected_read`, `sudo_not_allowed`, `docker`, …).
- **Daily statistics** — blocks / overrides per day (purely aggregated, no
  payload).

## Usage

```bash
python3 guard-audit.py                       # all views, terminal, English
python3 guard-audit.py --lang de             # German
python3 guard-audit.py --overrides           # override report only
python3 guard-audit.py --blocks              # block report only
python3 guard-audit.py --html                # HTML export (sanitized) to the default location
python3 guard-audit.py --html --full         # HTML WITH real commands/paths (private!)
python3 guard-audit.py --html report.html    # HTML to a custom path
```

### Filters (all combinable)

```
--since 2026-07-01   --until 2026-07-11   --session <id>
--actor main         --tool Bash          --reason docker
--file <path>        # a different actions.jsonl
```

## HTML export & upload protection

The terminal report is always full (no file artifact, cannot leak).
The **HTML export is protected on several levels** — honestly broken down:

**The load-bearing layer (the same on every system, regardless of platform):**
- **sanitized by default** — the HTML contains **no** task texts, commands,
  paths or session IDs by default, only structure and statistics. Safe to
  store and share. `--full` produces the full report (see warning below).

**Situational bonuses (apply depending on the system, 0–4 of them):**
- **Storage location** `~/.cache/guard-audit/report.html` — not a git repo
  (prevents accidental commits), fixed filename (self-overwrite instead of
  file sprawl).
- **`CACHEDIR.TAG`** in the cache folder → convention-following backup tools
  (borg `--exclude-caches`, restic, tar, …) skip it automatically.
- **File permissions** `600` / directory `700` (effective on Unix; on
  Windows, OS user isolation carries this).
- **`.gitignore`** — applies if `--html ./x.html` is still used to export
  into *this* repo (not into other projects!).
- **Warning** if an explicit `--html` target lies inside a git repo.
- Marking (`robots noindex`, marker comment) — a label only, **not** a
  protection.

### For users who want to play it safe (order = priority)

1. **The default export is harmless (sanitized)** — you can store and share
   it without concern.
2. **`--full` produces a report with real commands/paths** — treat it like a
   password: do not commit it, do not put it in a cloud-synced folder, do
   not send it.
3. The storage location is `~/.cache/guard-audit/` (excluded from
   convention-following backups via `CACHEDIR.TAG`). If you run a naive
   backup (`rsync` of the whole home directory), exclude `~/.cache` yourself
   — or simply stick to the default export.

## Data source

The hook writes every decision as one JSON line:
`ts, session_id, actor, agent_type, tool, target (redacted), decision, reason, level`.
`guard-audit` changes nothing — it only reads.
