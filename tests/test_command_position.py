# ============================================================================
# Lebenszyklus-Regel: Der Container-Befehl muss an der BEFEHLSPOSITION stehen.
#
# Die erste Fassung suchte den Befehl ueberall in der Zeile. Damit lehnte sie
# Dokumentationszeilen, Commit-Nachrichten und Suchmuster ab, in denen er
# blosser TEXT ist -- dieselbe Klasse wie beim zitierten Umleitungszeichen:
# Muster trifft Text statt Befehlsposition.
#
# Die Gegenrichtung ist die wichtigere und deshalb hier mitgetestet: Eine
# Verengung, die VERPACKUNGEN uebersieht (`timeout`, `nice`, `xargs`), tauscht
# einen Fehlalarm gegen ein Loch. Gemessen waren genau drei solche Loecher
# entstanden, bevor die Pruefung umgedreht wurde: Ein Container-Wort hinter dem
# Kommando zaehlt, ausser das Kommando ist ein reines Textwerkzeug. Eine Luecke
# in dieser Liste kostet einen Fehlalarm, nie einen Durchlass.
#
# Reiner DRY-RUN: Der Hook wird via stdin-JSON aufgerufen und NUR die
# Entscheidung geprueft (Exit 0 = allow, 2 = block). Es wird kein Befehl
# ausgefuehrt, kein Container angefasst.
# ============================================================================
import json
import os
import subprocess
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
HOOK = REPO / "hooks" / "command-guard.py"
EXAMPLE_RULES = REPO / "security-rules.example.json"

ALLOW = 0
BLOCK = 2

C = "some-container"


def _run(command: str) -> int:
    """Hook als PreToolUse-Dry-run aufrufen, Exit-Code zurueckgeben."""
    with tempfile.TemporaryDirectory() as ov:
        payload = {
            "session_id": "command-position-test",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": command},
        }
        env = dict(os.environ)
        env["CLAUDE_SECURITY_RULES"] = str(EXAMPLE_RULES)
        env["CLAUDE_SUDO_OVERRIDES_DIR"] = ov
        env["CLAUDE_AUDIT_DIR"] = ov
        env["CLAUDE_HOOK_DEV_FLAG"] = ov + "/_none"   # Dev-Modus garantiert aus
        p = subprocess.run(
            ["python3", str(HOOK)],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            env=env,
        )
        return p.returncode


# (case_id, command, expected)
CASES = [
    # --- A. Blosser TEXT -- muss frei laufen (der Fehlalarm) ---------------
    ("text-commit",
     'git commit -m "Guard: docker stop now needs an approval"',       ALLOW),
    ("text-suchmuster",
     'grep -rn "docker rm -f" docs/',                                  ALLOW),
    # OHNE Anfuehrungszeichen: Hier greift die Zerlegung nicht mehr, sondern
    # allein die Liste der Textwerkzeuge. Ohne diesen Fall waere sie unbelegt.
    ("text-suchwort-nackt",  'grep -rn docker docs/',                  ALLOW),
    ("text-meldung",         'echo "Example: docker system prune -af"', ALLOW),
    # Zitierter Text hinter einem Kommando, das KEIN bekanntes Textwerkzeug
    # ist. Hier hilft die Liste nicht -- nur die Zerlegung, die zitierten Text
    # als ein einziges Token behandelt.
    ("text-eigenes-werkzeug",
     'python3 tool.py --message "docker rm -f was rejected"',          ALLOW),
    ("text-pfadname",        'ls -la /home/user/docker-compose-templates/', ALLOW),
    ("text-dateiname",       'cat notes-docker-prune.md',              ALLOW),

    # --- B. Wird AUSGEFUEHRT -- muss blocken (die Luecke) ------------------
    ("run-blank",            f"docker rm -f {C}",                      BLOCK),
    ("run-voller-pfad",      f"/usr/bin/docker stop {C}",              BLOCK),
    ("run-timeout",          f"timeout 30 docker stop {C}",            BLOCK),
    ("run-nice",             f"nice docker rm -f {C}",                 BLOCK),
    ("run-xargs",            f"xargs -I{{}} docker rm -f {{}}",        BLOCK),
    ("run-bash-c",           f'bash -c "docker rm -f {C}"',            BLOCK),
    ("run-sh-c",             f"sh -c 'docker stop {C}'",               BLOCK),
    ("run-hintergrund",      f"nohup docker stop {C} &",               BLOCK),
    ("run-env-zuweisung",    f"DOCKER_HOST=x docker stop {C}",         BLOCK),
    ("run-nach-text",        f'echo "docker ps" && docker rm -f {C}',  BLOCK),
    ("run-fern",             f'ssh host "docker rm -f {C}"',           BLOCK),
    ("run-zeilenumbruch",    f'echo hello\ndocker rm -f {C}',          BLOCK),
]


def run_all():
    return [(cid, cmd, expected, (rc := _run(cmd)), rc == expected)
            for cid, cmd, expected in CASES]


try:
    import pytest

    @pytest.mark.parametrize("cid,cmd,expected", CASES)
    def test_command_position(cid, cmd, expected):
        assert _run(cmd) == expected, f"{cid}: {cmd!r}"

except ImportError:
    pass


# --- Standalone-Runner (ohne pytest) ---
if __name__ == "__main__":
    res = run_all()
    for cid, cmd, expected, rc, ok in res:
        tag = "PASS" if ok else "FAIL"
        exp = "allow" if expected == ALLOW else "block"
        got = "allow" if rc == ALLOW else ("block" if rc == BLOCK else f"rc={rc}")
        print(f"{tag}  {cid:24s} exp={exp:5s} got={got:5s}  {cmd!r}")
    passed = sum(1 for *_, ok in res if ok)
    print(f"\nBefehlsposition: {passed}/{len(res)} passed")
    raise SystemExit(0 if passed == len(res) else 1)
