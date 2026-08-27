#!/usr/bin/env python3
"""Session-start check: is a newer guard published than the one installed?

WHY THIS IS NOT IN THE GUARD ITSELF
-----------------------------------
command-guard.py runs on EVERY tool call. A network request there would slow
down every single action. This runs once per session start and throttles itself
to one real check per interval, so the usual session start does nothing but read
a timestamp.

WHY IT ONLY COMPUTES, AND DOES NOT TALK
---------------------------------------
Comparing versions is arithmetic, not understanding. This script writes one
finished sentence to stdout; the assistant reads it and tells the user in plain
language. Same channel the memory hook already uses.

OPT-IN, NOT OPT-OUT
-------------------
The check is OFF unless the user turns it on in ~/.claude/guard-config.json.
A security tool that phones home uninvited spends the trust it needs. Without
the key nothing leaves this machine — the script then prints a one-time note
that the feature exists, and never again.

WHAT IT WILL NOT DO
-------------------
- It does not install anything. It reports; installing is a separate, deliberate
  step with a test run and a rollback.
- It does not execute anything it fetched. The response is read as text, must
  match a strict pattern, and is compared. Nothing else.
- It never fails loudly. No network, GitHub down, garbage response, unreadable
  config — all of it ends in silence. A daily error message about an optional
  convenience is worse than no convenience.
"""
import json
import os
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
HOME = Path.home()

CONFIG_PATH = Path(os.environ.get("CLAUDE_UPDATE_CONFIG")
                   or os.environ.get("CLAUDE_GUARD_CONFIG")
                   or HOME / ".claude" / "guard-config.json")
STATE_PATH = Path(os.environ.get("CLAUDE_UPDATE_STATE")
                  or HOME / ".claude" / ".update-check-state.json")

# The published version is read from the latest RELEASE, not from the tip of a
# branch. "A newer version is available" has to mean something a person can go
# and look at: main moves several times a day, and pointing at it once meant
# announcing a state that was one merge old before anyone read the sentence.
DEFAULT_SOURCE = ("https://api.github.com/repos/inoX-Network/"
                  "claude-code-safety-guard/releases/latest")
DEFAULT_INTERVAL_HOURS = 24
FETCH_TIMEOUT_SECONDS = 5

# A version is a date, optionally with a counter: 2026.08.21, 2026.08.27-2.
# The counter exists because a date alone cannot separate two releases on the
# same day — measured on 2026-08-27, when eleven commits landed and two of them
# changed what the guard blocks: one before the bump, one after. The second was
# never announced, and no amount of discipline would have helped, because the
# string had nowhere left to move.
VERSION_RE = re.compile(r"^\d{4}\.\d{2}\.\d{2}(?:-\d{1,3})?$")

# Enough for a release payload; the value is picked out of it by key.
MAX_RESPONSE_BYTES = 65536


def _as_sortable(version: str) -> tuple[int, int, int, int]:
    """Order two versions. String comparison gets -10 and -2 the wrong way round."""
    head, _, counter = version.partition("-")
    year, month, day = (int(part) for part in head.split("."))
    return year, month, day, int(counter or 0)

# Built-in English, same arrangement as the guard: the configured language wins,
# English is always there as the floor. The texts live here rather than in the
# guard's catalogue so this script stays standalone — it must run even where the
# guard itself is not installed yet.
_MESSAGES = {
    "update.available":
        "A newer version of the guard is published: {published} (installed: "
        "{installed}). What changed is listed in CHANGELOG.md, which marks "
        "which entries close a way around the guard. Say the word if you want "
        "it looked up.",
    "update.feature_exists":
        "The guard can check once a day whether a newer version is published. "
        "That is TURNED OFF and contacts nothing. To enable it, set "
        "update_check.enabled to true in ~/.claude/guard-config.json.",
}


def _texts(config: dict) -> dict:
    """Built-in English, overlaid with the configured language if one exists."""
    texts = dict(_MESSAGES)
    code = config.get("language")
    # A code is a code, not a path: without this, '../../etc/passwd' would turn
    # a language setting into a file lookup.
    if not isinstance(code, str) or not re.fullmatch(r"[a-z]{2}(-[A-Z]{2})?", code):
        return texts
    lang_dir = (config.get("installation") or {}).get("lang_dir")
    folder = Path(os.path.expanduser(lang_dir)) if isinstance(lang_dir, str) \
        else HERE / "lang"
    catalogue = _read_json(folder / f"{code}.json")
    for key in texts:
        value = catalogue.get(key)
        if isinstance(value, str) and value:
            texts[key] = value
    return texts


def _read_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError, ValueError):
        return {}


def _installed_version() -> str | None:
    """The VERSION file shipped next to the hook."""
    for candidate in (HERE.parent / "VERSION", HERE / "VERSION"):
        try:
            value = candidate.read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if VERSION_RE.match(value):
            return value
    return None


def _settings(config: dict) -> tuple[bool, int, str]:
    """(enabled, interval_hours, source)"""
    section = config.get("update_check")
    if not isinstance(section, dict):
        return False, DEFAULT_INTERVAL_HOURS, DEFAULT_SOURCE
    enabled = section.get("enabled") is True
    interval = section.get("interval_hours", DEFAULT_INTERVAL_HOURS)
    if not isinstance(interval, int) or isinstance(interval, bool) or interval < 1:
        interval = DEFAULT_INTERVAL_HOURS
    source = section.get("source") or DEFAULT_SOURCE
    if not isinstance(source, str) or not source.startswith("https://"):
        # Refuse plain http: an unencrypted answer could be tampered with in
        # transit, and this one decides what the user is told about security.
        source = DEFAULT_SOURCE
    return enabled, interval, source


def _due(state: dict, interval_hours: int) -> bool:
    stamp = state.get("last_check")
    if not isinstance(stamp, str):
        return True
    try:
        last = datetime.fromisoformat(stamp)
    except ValueError:
        return True
    if last.tzinfo is None:
        last = last.replace(tzinfo=timezone.utc)
    age_hours = (datetime.now(timezone.utc) - last).total_seconds() / 3600
    return age_hours >= interval_hours


def _save_state(state: dict) -> None:
    try:
        STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
        STATE_PATH.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    except OSError:
        pass          # a state file we cannot write only costs an extra check


def _fetch_published(source: str) -> str | None:
    """Fetch the published version. Returns None on ANY problem."""
    try:
        request = urllib.request.Request(
            source, headers={"User-Agent": "claude-code-safety-guard-update-check"})
        with urllib.request.urlopen(request, timeout=FETCH_TIMEOUT_SECONDS) as answer:
            raw = answer.read(MAX_RESPONSE_BYTES)
    except (urllib.error.URLError, OSError, ValueError):
        return None
    try:
        text = raw.decode("utf-8").strip()
    except UnicodeDecodeError:
        return None

    # A releases endpoint answers with JSON; a plain VERSION file with a line.
    # Both are accepted, because an installation may point `source` at either —
    # and in both cases the value has to survive the same strict pattern before
    # it is used for anything.
    if text.startswith("{"):
        try:
            value = str(json.loads(text).get("tag_name") or "").strip()
        except (json.JSONDecodeError, AttributeError, TypeError):
            return None
    else:
        value = text

    value = value[1:] if value.startswith("v") else value
    return value if VERSION_RE.match(value) else None


def main() -> int:
    installed = _installed_version()
    config = _read_json(CONFIG_PATH)
    enabled, interval, source = _settings(config)

    texts = _texts(config)

    if not enabled:
        # Off. Say so ONCE, so the feature is discoverable without nagging.
        state = _read_json(STATE_PATH)
        if not state.get("informed_about_feature"):
            state["informed_about_feature"] = True
            _save_state(state)
            print(texts["update.feature_exists"])
        return 0

    if installed is None:
        return 0          # no version file: nothing to compare, stay quiet

    state = _read_json(STATE_PATH)
    if not _due(state, interval):
        return 0

    published = _fetch_published(source)
    state["last_check"] = datetime.now(timezone.utc).isoformat()
    if published is None:
        _save_state(state)
        return 0          # unreachable or unusable: silence, try again later

    state["last_published"] = published
    _save_state(state)

    if _as_sortable(published) > _as_sortable(installed):
        try:
            print(texts["update.available"].format(published=published,
                                                   installed=installed))
        except (KeyError, IndexError, ValueError):
            # A broken translation must not swallow the notice itself.
            print(_MESSAGES["update.available"].format(published=published,
                                                       installed=installed))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        # Belt and braces: a session start must never break because an optional
        # convenience stumbled.
        sys.exit(0)
