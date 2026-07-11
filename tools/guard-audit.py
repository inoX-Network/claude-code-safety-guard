#!/usr/bin/env python3
"""guard-audit — analysis tool for the command-guard audit log (actions.jsonl).

Three views from a single source (the JSONL audit log that the hook writes
anyway):

  1. Override report — which overrides were granted when, for which task
     (from the `decision == "activated"` lines written by the override-grant
     script).
  2. Block report   — which actions the guard blocked and why (from
     `decision == "block"`, aggregated by reason category).
  3. Daily statistics — blocks / overrides per day (purely aggregated, no
     payload).

Read-only. Standard library only. Does NOT read the protected
.sudo-overrides directory — all override info is already in the log.

── Upload/leak protection for the HTML export ────────────────────────────────
Load-bearing layer (the same on every system): the HTML export is SANITIZED
by default (no task texts, no commands/paths, no session IDs). `--full`
produces the full report — treat that like a password.

Situational bonuses (apply depending on the system):
  * Default location ~/.cache/guard-audit/report.html (not a git repo, fixed
    filename = self-overwrite) + CACHEDIR.TAG → convention-following backup
    tools (borg --exclude-caches, restic, tar, ...) skip the folder.
  * File chmod 600, directory 700 (effective on Unix; on Windows, OS user
    isolation carries this).
  * Warning if an explicit --html target lies inside a git repo.
  * Marking in the HTML (robots noindex + marker) — a label only, not an
    actual protection.
"""
from __future__ import annotations

import argparse
import html as _html
import json
import os
import stat
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

# ── Bilingual labels (user-facing strings, DE/EN switch) ──────────────────────
LABELS = {
    "de": {
        "title": "command-guard — Audit-Auswertung",
        "generated": "Erstellt",
        "source": "Quelle",
        "lines_total": "Zeilen gesamt",
        "lines_bad": "unlesbare Zeilen",
        "ov_head": "Override-Report — Freigaben",
        "ov_none": "Keine Override-Freigaben im Zeitraum.",
        "ov_date": "Datum",
        "ov_id": "Override",
        "ov_level": "Stufe",
        "ov_dur": "Dauer",
        "ov_actor": "Freigeber",
        "ov_task": "Aufgabe",
        "bl_head": "Block-Report — geblockte Aktionen",
        "bl_none": "Keine Blocks im Zeitraum.",
        "bl_reason": "Kategorie",
        "bl_count": "Anzahl",
        "bl_tool": "Werkzeug",
        "bl_detail": "haeufigste Details",
        "st_head": "Tages-Statistik",
        "st_day": "Tag",
        "st_blocks": "Blocks",
        "st_overrides": "Overrides",
        "summary": "Zusammenfassung",
        "dec_allow": "erlaubt",
        "dec_block": "geblockt",
        "dec_activated": "Override aktiviert",
        "min": "Min.",
        "toggle": "English",
        "sanitized_note": "Bereinigte Ansicht (ohne Aufgaben-Texte, Befehle, "
                          "Pfade, Session-IDs) — gefahrlos ablegbar.",
        "full_note": "VOLLER Report mit echten Befehlen/Pfaden — wie ein "
                     "Passwort behandeln: nicht committen, nicht teilen.",
        "redacted": "—",
    },
    "en": {
        "title": "command-guard — audit review",
        "generated": "Generated",
        "source": "Source",
        "lines_total": "total lines",
        "lines_bad": "unreadable lines",
        "ov_head": "Override report — grants",
        "ov_none": "No override grants in range.",
        "ov_date": "Date",
        "ov_id": "Override",
        "ov_level": "Level",
        "ov_dur": "Duration",
        "ov_actor": "Granted by",
        "ov_task": "Task",
        "bl_head": "Block report — blocked actions",
        "bl_none": "No blocks in range.",
        "bl_reason": "Category",
        "bl_count": "Count",
        "bl_tool": "Tool",
        "bl_detail": "top details",
        "st_head": "Daily statistics",
        "st_day": "Day",
        "st_blocks": "Blocks",
        "st_overrides": "Overrides",
        "summary": "Summary",
        "dec_allow": "allowed",
        "dec_block": "blocked",
        "dec_activated": "override activated",
        "min": "min",
        "toggle": "Deutsch",
        "sanitized_note": "Sanitized view (no task texts, commands, paths or "
                          "session IDs) — safe to store and share.",
        "full_note": "FULL report with real commands/paths — treat like a "
                     "password: do not commit, do not share.",
        "redacted": "—",
    },
}

_CACHEDIR_TAG = (
    "Signature: 8a477f597d28d172789f06886806bc55\n"
    "# This file is a cache directory tag created by guard-audit.\n"
    "# For information about cache directory tags, see "
    "https://bford.info/cachedir/\n"
)


def default_log_path() -> Path:
    d = os.environ.get("CLAUDE_AUDIT_DIR")
    return (Path(d) / "actions.jsonl") if d else (
        Path.home() / ".claude" / ".agent-audit" / "actions.jsonl")


def default_html_path() -> Path:
    """Fixed, private, backup-exempt default location (XDG cache)."""
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "guard-audit" / "report.html"


# ── Loading ─────────────────────────────────────────────────────────────────
def load_entries(path: Path):
    entries, total, bad = [], 0, 0
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            total += 1
            try:
                entries.append(json.loads(line))
            except (json.JSONDecodeError, ValueError):
                bad += 1
    return entries, total, bad


def _parse_ts(entry):
    ts = entry.get("ts")
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts)
    except ValueError:
        return None


def apply_filters(entries, args):
    since = datetime.fromisoformat(args.since) if args.since else None
    until = datetime.fromisoformat(args.until) if args.until else None
    out = []
    for e in entries:
        ts = _parse_ts(e)
        if since and ts and ts.replace(tzinfo=None) < since:
            continue
        if until and ts and ts.replace(tzinfo=None) > until:
            continue
        if args.session and e.get("session_id") != args.session:
            continue
        if args.actor and e.get("actor") != args.actor:
            continue
        if args.tool and e.get("tool") != args.tool:
            continue
        if args.reason and args.reason not in str(e.get("reason", "")):
            continue
        out.append(e)
    return out


def split_task(reason: str):
    """Splits 'task=XXX; minuten=N' into (task, minutes)."""
    if not reason:
        return "", None
    task, minutes = reason, None
    if "; minuten=" in reason:
        head, _, tail = reason.rpartition("; minuten=")
        if tail.strip().isdigit():
            task, minutes = head, tail.strip()
    if task.startswith("task="):
        task = task[len("task="):]
    return task.strip(), minutes


# ── Aggregation ─────────────────────────────────────────────────────────────
def override_rows(entries):
    rows = []
    for e in entries:
        if e.get("decision") != "activated":
            continue
        task, minutes = split_task(e.get("reason", ""))
        rows.append({
            "ts": _parse_ts(e),
            "id": Path(str(e.get("target", ""))).stem or "?",
            "level": e.get("level"),
            "minutes": minutes,
            "actor": e.get("actor") or "?",
            "task": task,
        })
    rows.sort(key=lambda r: r["ts"] or datetime.min)
    return rows


def block_groups(entries, examples_per=3):
    groups = defaultdict(list)
    for e in entries:
        if e.get("decision") != "block":
            continue
        category = str(e.get("reason", "?")).split(":", 1)[0]
        groups[category].append(e)
    out = []
    for category, items in groups.items():
        items.sort(key=lambda e: _parse_ts(e) or datetime.min, reverse=True)
        detail = Counter(
            str(e.get("reason", "")).split(":", 1)[1]
            for e in items if ":" in str(e.get("reason", ""))
        )
        out.append({
            "reason": category,
            "count": len(items),
            "tools": Counter(i.get("tool", "?") for i in items),
            "detail": detail,
            "examples": items[:examples_per],
        })
    out.sort(key=lambda g: g["count"], reverse=True)
    return out


def daily_stats(entries):
    """Blocks/overrides per calendar day — purely aggregated, no payload."""
    days = defaultdict(lambda: {"block": 0, "activated": 0})
    for e in entries:
        ts = _parse_ts(e)
        d = e.get("decision")
        if not ts or d not in ("block", "activated"):
            continue
        days[ts.strftime("%Y-%m-%d")][d] += 1
    return [(day, v["block"], v["activated"]) for day, v in sorted(days.items())]


def summary(entries):
    return Counter(e.get("decision", "?") for e in entries)


# ── CLI output ──────────────────────────────────────────────────────────────
def _fmt_ts(ts):
    return ts.strftime("%Y-%m-%d %H:%M") if ts else "?"


def _table(headers, rows, max_widths=None):
    cols = len(headers)
    widths = [len(h) for h in headers]
    srows = [[str(c) for c in r] for r in rows]
    for r in srows:
        for i in range(cols):
            widths[i] = max(widths[i], len(r[i]))
    if max_widths:
        for i, mw in enumerate(max_widths):
            if mw:
                widths[i] = min(widths[i], mw)

    def cut(s, w):
        return s if len(s) <= w else s[: w - 1] + "…"

    head = "  ".join(cut(h, widths[i]).ljust(widths[i]) for i, h in enumerate(headers))
    sep = "  ".join("─" * widths[i] for i in range(cols))
    body = "\n".join(
        "  ".join(cut(r[i], widths[i]).ljust(widths[i]) for i in range(cols))
        for r in srows)
    return f"{head}\n{sep}\n{body}"


def _bar(n, mx, width=24):
    return "█" * (round(n / mx * width) if mx else 0)


def render_cli(L, path, total, bad, entries, ov, blocks, days, show_ov, show_bl):
    # CLI output is always full (no file artifact, cannot leak).
    out = [f"\n{L['title']}", f"{L['source']}: {path}",
           f"{L['lines_total']}: {total}   {L['lines_bad']}: {bad}"]
    ss = summary(entries)
    out.append(f"{L['summary']}: {L['dec_allow']}={ss.get('allow',0)}  "
               f"{L['dec_block']}={ss.get('block',0)}  "
               f"{L['dec_activated']}={ss.get('activated',0)}")

    if days:
        out.append(f"\n── {L['st_head']} ──")
        mxb = max((b for _, b, _ in days), default=0)
        for day, b, o in days[-14:]:
            out.append(f"  {day}  {L['st_blocks']:>7} {b:>3} {_bar(b, mxb, 20):<20} "
                       f"{L['st_overrides']}:{o}")

    if show_ov:
        out.append(f"\n── {L['ov_head']} ──")
        if not ov:
            out.append(L["ov_none"])
        else:
            rows = [[_fmt_ts(r["ts"]), r["id"], str(r["level"]),
                     f"{r['minutes']} {L['min']}" if r["minutes"] else "-",
                     r["actor"], r["task"].replace("\n", " ")] for r in ov]
            out.append(_table(
                [L["ov_date"], L["ov_id"], L["ov_level"], L["ov_dur"],
                 L["ov_actor"], L["ov_task"]],
                rows, max_widths=[16, 28, 5, 10, 14, 66]))

    if show_bl:
        out.append(f"\n── {L['bl_head']} ──")
        if not blocks:
            out.append(L["bl_none"])
        else:
            rows = [[g["reason"], str(g["count"]),
                     ", ".join(f"{t}:{n}" for t, n in g["tools"].most_common(2)),
                     ", ".join(d for d, _ in g["detail"].most_common(3)) or "-"]
                    for g in blocks]
            out.append(_table(
                [L["bl_reason"], L["bl_count"], L["bl_tool"], L["bl_detail"]],
                rows, max_widths=[26, 7, 22, 46]))
    return "\n".join(out)


# ── HTML export (sanitized default; --full opt-in) ─────────────────────────
def render_html(path, total, bad, entries, ov, blocks, days, sanitized):
    ss = summary(entries)

    def esc(s):
        return _html.escape(str(s), quote=True)

    def bi(key):
        return (f'<span data-de="{esc(LABELS["de"][key])}" '
                f'data-en="{esc(LABELS["en"][key])}"></span>')

    # Daily statistics bars (always allowed — pure aggregate numbers)
    mxb = max((b for _, b, _ in days), default=1) or 1
    day_rows = "\n".join(
        f'<tr><td class="mono">{esc(d)}</td>'
        f'<td class="c">{b}</td>'
        f'<td><span class="bar" style="width:{round(b/mxb*100)}%"></span></td>'
        f'<td class="c">{o}</td></tr>' for d, b, o in days) or \
        '<tr><td colspan=4>—</td></tr>'

    if sanitized:
        # Override report: metadata without payload (no ID, no task).
        ov_rows = "\n".join(
            f'<tr><td>{esc(_fmt_ts(r["ts"]))}</td><td class="c">{esc(r["level"])}</td>'
            f'<td class="c">{esc(str(r["minutes"])+" min") if r["minutes"] else "-"}</td>'
            f'<td>{esc(r["actor"])}</td></tr>' for r in ov) or \
            '<tr><td colspan=4>—</td></tr>'
        ov_head = (f'<th>{bi("ov_date")}</th><th>{bi("ov_level")}</th>'
                   f'<th>{bi("ov_dur")}</th><th>{bi("ov_actor")}</th>')
        # Block report: category + count + tool, WITHOUT detail suffixes/examples.
        bl_rows = "\n".join(
            f'<tr><td class="mono">{esc(g["reason"])}</td><td class="c">{g["count"]}</td>'
            f'<td>{", ".join(f"{esc(t)}:{n}" for t, n in g["tools"].most_common(4))}</td></tr>'
            for g in blocks) or '<tr><td colspan=3>—</td></tr>'
        bl_head = (f'<th>{bi("bl_reason")}</th><th>{bi("bl_count")}</th>'
                   f'<th>{bi("bl_tool")}</th>')
    else:
        ov_rows = "\n".join(
            f'<tr><td>{esc(_fmt_ts(r["ts"]))}</td><td class="mono">{esc(r["id"])}</td>'
            f'<td class="c">{esc(r["level"])}</td>'
            f'<td class="c">{esc(str(r["minutes"])+" min") if r["minutes"] else "-"}</td>'
            f'<td>{esc(r["actor"])}</td><td>{esc(r["task"])}</td></tr>' for r in ov) or \
            '<tr><td colspan=6>—</td></tr>'
        ov_head = (f'<th>{bi("ov_date")}</th><th>{bi("ov_id")}</th><th>{bi("ov_level")}</th>'
                   f'<th>{bi("ov_dur")}</th><th>{bi("ov_actor")}</th><th>{bi("ov_task")}</th>')
        bl_rows_list = []
        for g in blocks:
            tools = ", ".join(f"{esc(t)}:{n}" for t, n in g["tools"].most_common(4))
            ex = "<br>".join(
                f'{esc(_fmt_ts(_parse_ts(e)))} · {esc(e.get("tool"))} · '
                f'<span class="mono">{esc(str(e.get("target",""))[:80])}</span>'
                for e in g["examples"])
            bl_rows_list.append(
                f'<tr><td class="mono">{esc(g["reason"])}</td><td class="c">{g["count"]}</td>'
                f'<td>{tools}</td><td class="ex">{ex}</td></tr>')
        bl_rows = "\n".join(bl_rows_list) or '<tr><td colspan=4>—</td></tr>'
        bl_head = (f'<th>{bi("bl_reason")}</th><th>{bi("bl_count")}</th>'
                   f'<th>{bi("bl_tool")}</th><th>{bi("ov_task")}</th>')

    gen = datetime.now().strftime("%Y-%m-%d %H:%M")
    bad_note = f" (+{bad})" if bad else ""
    note_key = "sanitized_note" if sanitized else "full_note"
    note_cls = "note-ok" if sanitized else "note-warn"
    marker = ("PRIVATE command-guard audit — do NOT commit, upload or share"
              if not sanitized else "sanitized command-guard summary")
    return f"""<!doctype html>
<!-- {marker} -->
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow,noarchive">
<title>command-guard audit</title>
<style>
  :root {{ color-scheme: light dark; --bg:#faf7f2; --fg:#2a2420; --line:#d8cfc2;
           --accent:#c47a4a; --block:#b4472e; --ok:#4a7a4a; --mono:#6b5f52; }}
  @media (prefers-color-scheme: dark) {{
    :root {{ --bg:#1c1815; --fg:#e8e0d6; --line:#3a332c; --accent:#d98a58;
             --block:#e0765a; --ok:#8fb98f; --mono:#a89a88; }} }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; padding:2rem 1rem; background:var(--bg); color:var(--fg);
          font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif; }}
  .wrap {{ max-width:1100px; margin:0 auto; }}
  header {{ display:flex; align-items:center; justify-content:space-between;
            gap:1rem; flex-wrap:wrap; border-bottom:2px solid var(--line);
            padding-bottom:1rem; margin-bottom:1rem; }}
  h1 {{ font-size:1.4rem; margin:0; }}
  h2 {{ font-size:1.1rem; margin:2rem 0 .6rem; color:var(--accent); }}
  .meta {{ color:var(--mono); font-size:.85rem; }}
  #lang {{ cursor:pointer; border:1px solid var(--line); background:transparent;
           color:var(--fg); border-radius:6px; padding:.4rem .8rem; font-size:.9rem; }}
  .note {{ border-radius:8px; padding:.6rem .9rem; margin:.4rem 0 1rem; font-size:.9rem; }}
  .note-ok {{ border:1px solid var(--ok); color:var(--ok); }}
  .note-warn {{ border:1px solid var(--block); color:var(--block); font-weight:600; }}
  .cards {{ display:flex; gap:.8rem; flex-wrap:wrap; }}
  .card {{ border:1px solid var(--line); border-radius:8px; padding:.6rem 1rem; }}
  .card b {{ font-size:1.3rem; display:block; }}
  table {{ width:100%; border-collapse:collapse; margin-top:.4rem; font-size:.9rem; }}
  th,td {{ text-align:left; padding:.45rem .6rem; border-bottom:1px solid var(--line);
           vertical-align:top; }}
  th {{ color:var(--mono); font-weight:600; }}
  td.c {{ text-align:center; }}
  .mono {{ font-family:ui-monospace,Menlo,Consolas,monospace; color:var(--mono);
           font-size:.85em; word-break:break-all; }}
  .ex {{ color:var(--mono); font-size:.8rem; }}
  .bar {{ display:inline-block; height:.7rem; background:var(--block);
          border-radius:3px; min-width:2px; }}
  .scroll {{ overflow-x:auto; }}
  footer {{ margin-top:2rem; padding-top:1rem; border-top:1px solid var(--line);
            color:var(--mono); font-size:.8rem; }}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div>
      <h1>{bi('title')}</h1>
      <div class="meta"><span>{bi('generated')}</span>: {esc(gen)} · <span>{bi('source')}</span>:
        <span class="mono">{esc(path)}</span></div>
    </div>
    <button id="lang" onclick="toggleLang()">{esc(LABELS['en']['toggle'])}</button>
  </header>

  <div class="note {note_cls}">{bi(note_key)}</div>

  <div class="cards">
    <div class="card"><span class="meta">{bi('lines_total')}</span><b>{total}{esc(bad_note)}</b></div>
    <div class="card"><span class="meta">{bi('dec_allow')}</span><b>{ss.get('allow',0)}</b></div>
    <div class="card"><span class="meta">{bi('dec_block')}</span><b>{ss.get('block',0)}</b></div>
    <div class="card"><span class="meta">{bi('dec_activated')}</span><b>{ss.get('activated',0)}</b></div>
  </div>

  <h2>{bi('st_head')}</h2>
  <div class="scroll"><table>
    <thead><tr><th>{bi('st_day')}</th><th>{bi('st_blocks')}</th><th></th><th>{bi('st_overrides')}</th></tr></thead>
    <tbody>{day_rows}</tbody></table></div>

  <h2>{bi('ov_head')}</h2>
  <div class="scroll"><table>
    <thead><tr>{ov_head}</tr></thead><tbody>{ov_rows}</tbody></table></div>

  <h2>{bi('bl_head')}</h2>
  <div class="scroll"><table>
    <thead><tr>{bl_head}</tr></thead><tbody>{bl_rows}</tbody></table></div>

  <footer>{esc(marker)}</footer>
</div>
<script>
function setLang(l) {{
  document.documentElement.lang = l;
  document.querySelectorAll('[data-de]').forEach(function(el) {{
    el.textContent = el.getAttribute('data-' + l);
  }});
  document.getElementById('lang').textContent =
    (l === 'de') ? '{esc(LABELS['de']['toggle'])}' : '{esc(LABELS['en']['toggle'])}';
  localStorage.setItem('guardAuditLang', l);
}}
function toggleLang() {{ setLang(document.documentElement.lang === 'de' ? 'en' : 'de'); }}
setLang(localStorage.getItem('guardAuditLang') || 'en');
</script>
</body>
</html>"""


# ── Writing the HTML file safely ─────────────────────────────────────────────
def _in_git_repo(p: Path):
    for parent in [p.resolve().parent, *p.resolve().parents]:
        if (parent / ".git").exists():
            return parent
    return None


def write_html_secure(target: Path, content: str, is_default: bool):
    """Writes the HTML with a 700 directory / 600 file, creates a
    CACHEDIR.TAG at the default location, and warns if an explicit
    target lies inside a git repo."""
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(target.parent, stat.S_IRWXU)  # 700
    except OSError:
        pass
    if is_default:
        tag = target.parent / "CACHEDIR.TAG"
        if not tag.exists():
            tag.write_text(_CACHEDIR_TAG, encoding="utf-8")
    else:
        repo = _in_git_repo(target)
        if repo:
            print(f"WARNING: {target} is inside the git repo {repo} — do not "
                  f"commit it! (The default location ~/.cache/guard-audit/ "
                  f"would be safer.)",
                  file=sys.stderr)
    # 600 permissions already at creation time (not only after writing)
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, content.encode("utf-8"))
    finally:
        os.close(fd)
    try:
        os.chmod(target, stat.S_IRUSR | stat.S_IWUSR)  # 600 (in case umask differed)
    except OSError:
        pass


# ── main ──────────────────────────────────────────────────────────────────────
def main(argv=None):
    p = argparse.ArgumentParser(
        description="Analysis tool for the command-guard audit log (actions.jsonl).")
    p.add_argument("--file", type=Path, default=None,
                   help="Path to actions.jsonl (default: ~/.claude/.agent-audit/)")
    p.add_argument("--lang", choices=("de", "en"), default="en", help="CLI language")
    p.add_argument("--overrides", action="store_true", help="override report only")
    p.add_argument("--blocks", action="store_true", help="block report only")
    p.add_argument("--html", nargs="?", const="__DEFAULT__", default=None,
                   metavar="FILE",
                   help="HTML export (without a path: ~/.cache/guard-audit/report.html)")
    p.add_argument("--full", action="store_true",
                   help="HTML WITH real commands/paths/tasks (otherwise sanitized)")
    p.add_argument("--since", help="from date, ISO format (e.g. 2026-07-01)")
    p.add_argument("--until", help="until date, ISO format")
    p.add_argument("--session", help="only this session_id")
    p.add_argument("--actor", help="only this actor (main / <agent-id> / user-via-!)")
    p.add_argument("--tool", help="only this tool")
    p.add_argument("--reason", help="substring filter on the block/grant reason")
    args = p.parse_args(argv)

    path = args.file or default_log_path()
    if not path.exists():
        print(f"Audit log not found: {path}", file=sys.stderr)
        return 2

    entries, total, bad = load_entries(path)
    entries = apply_filters(entries, args)
    ov = override_rows(entries)
    blocks = block_groups(entries)
    days = daily_stats(entries)

    show_ov = args.overrides or not args.blocks
    show_bl = args.blocks or not args.overrides
    L = LABELS[args.lang]

    print(render_cli(L, path, total, bad, entries, ov, blocks, days, show_ov, show_bl))

    if args.html is not None:
        is_default = args.html == "__DEFAULT__"
        target = default_html_path() if is_default else Path(args.html)
        sanitized = not args.full
        html = render_html(path, total, bad, entries, ov, blocks, days, sanitized)
        write_html_secure(target, html, is_default)
        mode = "sanitized" if sanitized else "FULL (private!)"
        print(f"\nHTML [{mode}]: {target}")
        if not sanitized:
            print("  -> contains real commands/paths — treat like a password.",
                  file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
