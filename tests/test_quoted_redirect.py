# ============================================================================
# Zitierte Umleitungszeichen im Write-Gate.
#
# Ein `>` INNERHALB von Anfuehrungszeichen ist Text, keine Umleitung. Der
# Teilstring-Test in _command_is_write kannte diesen Unterschied nicht: Jeder
# Befehl, der einen Pfeil in eine MELDUNG schrieb und dabei einen geschuetzten
# Pfad nannte, galt als Schreibversuch -- also genau die harmlosen
# Diagnose-Einzeiler.
#
# Die Gegenrichtung ist genauso wichtig und deshalb hier mitgetestet: Ein
# UNZITIERTER Pfeil ist eine echte Umleitung (`echo x -> datei` schreibt in
# `datei`), und eine per `eval`/`bash -c` weitergereichte Zeichenkette wird
# ausgefuehrt, auch wenn sie in Anfuehrungszeichen steht. Beides muss weiter
# blocken -- sonst waere aus dem Fehlalarm-Fix ein Loch geworden.
#
# Reiner DRY-RUN wie test_write_indicators_matrix.py: Der Hook wird via
# stdin-JSON aufgerufen und NUR die Entscheidung geprueft (Exit 0 = allow,
# 2 = block). Es wird nichts ausgefuehrt und nichts geschrieben. Schutzzone ist
# ein Wegwerf-Pfad; echte Schutzpfade werden nie beruehrt.
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

ZONE = "/tmp/guard-test-quoted"   # simulierter protected_path, nie real beschrieben


def _make_rules() -> str:
    rules = json.loads(EXAMPLE_RULES.read_text(encoding="utf-8"))
    rules["blocked_paths_write"] = [ZONE]
    tf = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
    json.dump(rules, tf)
    tf.close()
    return tf.name


def _run(command: str, rules_path: str) -> int:
    """Hook als PreToolUse-Dry-run aufrufen, Exit-Code zurueckgeben."""
    with tempfile.TemporaryDirectory() as ov:
        payload = {
            "session_id": "quoted-redirect-test",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": command},
        }
        env = dict(os.environ)
        env["CLAUDE_SECURITY_RULES"] = rules_path
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
    # --- neu erlaubt: das Groesser-Zeichen steht in Anfuehrungszeichen ---------
    ("pfeil-in-text",     f'echo "wert -> ok"; cat {ZONE}/f',                ALLOW),
    ("pfeil-mit-subst",   f'echo "datei -> $(cat {ZONE}/f)"',                ALLOW),
    ("groesser-in-text",  f'echo "a > b ist wahr"; cat {ZONE}/f',            ALLOW),
    ("lesen-schlicht",    f'cat {ZONE}/f',                                   ALLOW),
    ("lese-umleitung",    f'wc -c < {ZONE}/f',                               ALLOW),

    # --- weiterhin geblockt: echte Schreibzugriffe ----------------------------
    ("echte-umleitung",   f'echo x > {ZONE}/f',                              BLOCK),
    ("anhaengen",         f'echo x >> {ZONE}/f',                             BLOCK),
    # `-` ist Argument, `> datei` der Redirect: das schreibt wirklich.
    ("pfeil-unzitiert",   f'echo x -> {ZONE}/f',                             BLOCK),
    # In Anfuehrungszeichen, aber von einer Shell ausgefuehrt.
    ("eval-verpackt",     f'eval "echo x > {ZONE}/f"',                       BLOCK),
    ("bash-c-verpackt",   f'bash -c "echo x > {ZONE}/f"',                    BLOCK),
    # Anfuehrungszeichen vorhanden, Umleitung aber ausserhalb davon.
    ("quote-und-redirect", f'echo "harmlos" > {ZONE}/f',                     BLOCK),
    ("schreib-verb",      f'rm {ZONE}/f',                                    BLOCK),
    ("in-place-edit",     f'sed -i s/a/b/ {ZONE}/f',                         BLOCK),
]


def run_all():
    rules = _make_rules()
    ergebnisse = []
    try:
        for cid, cmd, expected in CASES:
            rc = _run(cmd, rules)
            ergebnisse.append((cid, cmd, expected, rc, rc == expected))
    finally:
        try:
            os.unlink(rules)
        except OSError:
            pass
    return ergebnisse


try:
    import pytest

    _RULES = _make_rules()

    @pytest.mark.parametrize("cid,cmd,expected", CASES)
    def test_quoted_redirect(cid, cmd, expected):
        assert _run(cmd, _RULES) == expected, f"{cid}: {cmd!r}"

except ImportError:
    pass


# --- Standalone-Runner (ohne pytest) ---
if __name__ == "__main__":
    res = run_all()
    for cid, cmd, expected, rc, ok in res:
        tag = "PASS" if ok else "FAIL"
        exp = "allow" if expected == ALLOW else "block"
        got = "allow" if rc == ALLOW else ("block" if rc == BLOCK else f"rc={rc}")
        print(f"{tag}  {cid:20s} exp={exp:5s} got={got:5s}  {cmd}")
    passed = sum(1 for *_, ok in res if ok)
    print(f"\nZitierte Umleitung: {passed}/{len(res)} passed")
    raise SystemExit(0 if passed == len(res) else 1)
