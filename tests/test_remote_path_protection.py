# ============================================================================
# Der Pfadschutz endet an der Fernzugriffs-Tuer.
#
# Lokal wird ein Ueberschreiben unter einem geschuetzten Pfad abgelehnt.
# Dieselbe Zeile, in Anfuehrungszeichen an ein Ziel geschickt, lief durch:
# Seit dem Quote-Stripping-Fix gelten Umleitungszeichen INNERHALB von
# Anfuehrungszeichen als Text. Fuer Ausgabetexte ist das richtig -- aber die
# Zeichenkette hinter `ssh` ist kein Text, sie wird auf der Gegenseite
# ausgefuehrt. Genau dafuer gibt es die Passthrough-Ausnahme; sie kannte
# `eval` und `bash -c`, nur `ssh` nicht (der Ausdruck verlangt ein `-c`,
# das ssh nicht hat).
#
# Zweite Tuer, hier mitgetestet: `scp` und `rsync` schreiben auf die
# Gegenseite, ohne dass etwas greift -- und das ist der normale Deploy-Weg,
# kein Randfall. `scp` steht in keiner Verb-Liste, `rsync` zaehlt bewusst nur
# mit Loeschflag als Schreibvorgang (sonst Fehlalarme bei jedem lesenden Lauf).
# Die Loesung entscheidet ueber die POSITION, nicht ueber das Vorkommen: Ein
# Argument der Form `ziel:/pfad` an letzter Stelle ist ein Schreibziel; steht
# dieselbe Form vorn, wird GEHOLT und bleibt frei.
#
# Die Gegenrichtung ist genauso wichtig und deshalb mitgetestet: Lesende
# Fernbefehle muessen weiter durchlaufen, und die Fehlalarm-Faelle aus
# test_quoted_redirect.py duerfen NICHT zurueckfallen. Eine Regel, die zu oft
# grundlos blockt, wird irgendwann nicht mehr gelesen -- dann schuetzt sie
# nichts mehr.
#
# Reiner DRY-RUN: Der Hook wird via stdin-JSON aufgerufen und NUR die
# Entscheidung geprueft (Exit 0 = allow, 2 = block). Es wird nichts ausgefuehrt,
# nichts geschrieben und keine Verbindung aufgebaut. Schutzzone ist ein
# Wegwerf-Pfad; echte Schutzpfade werden nie beruehrt.
# ============================================================================
import json
import os
import subprocess
import tempfile

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOOK = os.path.join(REPO, "hooks", "command-guard.py")
EXAMPLE_RULES = os.path.join(REPO, "security-rules.example.json")

ALLOW = 0
BLOCK = 2

ZONE = "/tmp/guard-test-remote"   # simulierter Serverpfad, nie real beschrieben
HOST = "deploy-target"            # frei erfundenes Ziel, nie kontaktiert


def _make_rules() -> str:
    rules = json.loads(open(EXAMPLE_RULES, encoding="utf-8").read())
    rules["blocked_paths_write"] = [ZONE]
    tf = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
    json.dump(rules, tf)
    tf.close()
    return tf.name


def _run(command: str, rules_path: str) -> int:
    """Hook als PreToolUse-Dry-run aufrufen, Exit-Code zurueckgeben."""
    with tempfile.TemporaryDirectory() as ov:
        payload = {
            "session_id": "remote-path-test",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": command},
        }
        env = dict(os.environ)
        env["CLAUDE_SECURITY_RULES"] = rules_path
        env["CLAUDE_SUDO_OVERRIDES_DIR"] = ov     # leer -> Stufe 0
        env["CLAUDE_AUDIT_DIR"] = ov
        env["CLAUDE_HOOK_DEV_FLAG"] = ov + "/_none"
        p = subprocess.run(
            ["python3", HOOK],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            env=env,
        )
        return p.returncode


# (case_id, command, expected)
CASES = [
    # --- Fernbefehl schreibt: muss blocken -----------------------------------
    ("fern-umleitung",       f'ssh {HOST} "echo x > {ZONE}/config.yml"',          BLOCK),
    ("fern-anhaengen",       f'ssh {HOST} "echo x >> {ZONE}/config.yml"',         BLOCK),
    ("fern-in-place-edit",   f'ssh {HOST} "sed -i s/a/b/ {ZONE}/config.yml"',     BLOCK),
    # Einfache Anfuehrungszeichen sind derselbe Fall.
    ("fern-einfach-zitiert", f"ssh {HOST} 'echo x > {ZONE}/config.yml'",          BLOCK),
    # Ziel mit Benutzer und Anschluss -- immer noch ein Fernzugriff.
    ("fern-mit-benutzer",    f'ssh deploy@{HOST} "echo x > {ZONE}/config.yml"',   BLOCK),
    # Eingabe wird lokal erzeugt, geschrieben wird auf der Gegenseite.
    ("fern-eingabe-umlenkt", f'cat ./neu.conf | ssh {HOST} "cat > {ZONE}/x.conf"', BLOCK),

    # --- Fernbefehl liest: muss durchlaufen -----------------------------------
    ("fern-lesen",           f'ssh {HOST} "cat {ZONE}/config.yml"',               ALLOW),
    ("fern-auflisten",       f'ssh {HOST} "ls -la {ZONE}"',                       ALLOW),
    ("fern-protokoll",       f'ssh {HOST} "tail -50 {ZONE}/app.log"',             ALLOW),
    ("fern-status",          f'ssh {HOST} "df -h"',                               ALLOW),

    # --- Uebertragung: Zielposition entscheidet -------------------------------
    ("uebertragung-hin",     f'scp ./config.yml {HOST}:{ZONE}/config.yml',        BLOCK),
    ("uebertragung-hin-user", f'scp ./config.yml deploy@{HOST}:{ZONE}/config.yml', BLOCK),
    ("abgleich-hin",         f'rsync -a ./build/ {HOST}:{ZONE}/',                 BLOCK),
    ("abgleich-hin-loeschen", f'rsync -a --delete ./build/ {HOST}:{ZONE}/',       BLOCK),
    # Gegenrichtung: es wird GEHOLT, nicht geschrieben -- muss frei bleiben.
    ("uebertragung-her",     f'scp {HOST}:{ZONE}/config.yml ./lokal.yml',         ALLOW),
    ("abgleich-her",         f'rsync -a {HOST}:{ZONE}/ ./lokal/',                 ALLOW),

    # --- Kein Rueckfall: die Fehlalarm-Faelle aus test_quoted_redirect.py -----
    ("pfeil-in-text",        f'echo "wert -> ok"; cat {ZONE}/f',                  ALLOW),
    ("groesser-in-text",     f'echo "a > b ist wahr"; cat {ZONE}/f',              ALLOW),
    ("lesen-schlicht",       f'cat {ZONE}/f',                                     ALLOW),

    # --- Gegenprobe: was lokal blockte, blockt weiter --------------------------
    ("lokal-umleitung",      f'echo x > {ZONE}/f',                                BLOCK),
    ("bash-c-verpackt",      f'bash -c "echo x > {ZONE}/f"',                      BLOCK),
    ("eval-verpackt",        f'eval "echo x > {ZONE}/f"',                         BLOCK),
    ("lokal-loeschen",       f'rm {ZONE}/f',                                      BLOCK),
]


@pytest.mark.parametrize("case_id,command,expected", CASES, ids=[c[0] for c in CASES])
def test_remote_path_protection(case_id, command, expected):
    rules = _make_rules()
    try:
        assert _run(command, rules) == expected
    finally:
        os.unlink(rules)
