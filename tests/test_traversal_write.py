# ============================================================================
# Getarnte Schreibziele im Pfad-Gate (check_blocked_paths).
#
# Der Abgleich in check_blocked_paths ist ein Teilstring-Vergleich. Ein Ziel, das
# ueber einen Umweg in die Schutzzone zeigt, enthaelt den Zonenpfad woertlich gar
# nicht: `/tmp/anderswo/../guard-test-trav/f` landet in der Zone, sieht aber nicht
# danach aus. Deshalb werden Umwege (/./, //, /seg/../) VOR dem Abgleich lexikalisch
# aufgeloest.
#
# Rein lexikalisch, kein Dateisystemzugriff -- Symlinks sind bewusst nicht Teil
# dieser Pruefung (eigenes Thema, s. THREAT-MODEL).
#
# Reiner DRY-RUN wie die anderen Matrizen: Der Hook wird via stdin-JSON aufgerufen
# und NUR die Entscheidung geprueft. Es wird nichts ausgefuehrt und nichts kopiert.
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

ZONE = "/tmp/guard-test-trav"     # simulierter protected_path, nie real beschrieben
NEBEN = "/tmp/guard-test-neben"   # unkritisch


def _make_rules() -> str:
    rules = json.loads(EXAMPLE_RULES.read_text(encoding="utf-8"))
    rules["blocked_paths_write"] = [ZONE]
    tf = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
    json.dump(rules, tf)
    tf.close()
    return tf.name


def _run(command: str, rules_path: str) -> int:
    with tempfile.TemporaryDirectory() as ov:
        payload = {
            "session_id": "traversal-test",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": command},
        }
        env = dict(os.environ)
        env["CLAUDE_SECURITY_RULES"] = rules_path
        env["CLAUDE_SUDO_OVERRIDES_DIR"] = ov
        env["CLAUDE_AUDIT_DIR"] = ov
        env["CLAUDE_HOOK_DEV_FLAG"] = ov + "/_none"
        p = subprocess.run(
            ["python3", str(HOOK)],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            env=env,
        )
        return p.returncode


CASES = [
    # --- Grundlinie: direkter Treffer und klarer Nicht-Treffer ----------------
    ("direkt",            f"cp /etc/hostname {ZONE}/f",                    BLOCK),
    ("daneben",           f"cp /etc/hostname {NEBEN}/f",                   ALLOW),

    # --- die eigentliche Zusage: Umwege werden aufgeloest ---------------------
    # Enthaelt den Zonenpfad woertlich NICHT, landet aber darin.
    ("umweg-von-aussen",  f"cp /etc/hostname {NEBEN}/../guard-test-trav/f", BLOCK),
    ("punkt-segment",     f"cp /etc/hostname {ZONE}/./f",                   BLOCK),
    ("doppelter-slash",   f"cp /etc/hostname {ZONE}//f",                    BLOCK),
    ("umweg-mit-redirect", f"echo x > {NEBEN}/../guard-test-trav/f",        BLOCK),
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
    def test_traversal_write(cid, cmd, expected):
        assert _run(cmd, _RULES) == expected, f"{cid}: {cmd!r}"

except ImportError:
    pass


if __name__ == "__main__":
    res = run_all()
    for cid, cmd, expected, rc, ok in res:
        tag = "PASS" if ok else "FAIL"
        exp = "allow" if expected == ALLOW else "block"
        got = "allow" if rc == ALLOW else ("block" if rc == BLOCK else f"rc={rc}")
        print(f"{tag}  {cid:20s} exp={exp:5s} got={got:5s}  {cmd}")
    passed = sum(1 for *_, ok in res if ok)
    print(f"\nTraversal-Umwege: {passed}/{len(res)} passed")
    raise SystemExit(0 if passed == len(res) else 1)
