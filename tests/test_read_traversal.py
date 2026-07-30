# ============================================================================
# Getarnte Lesepfade im Leseschutz (check_read_protection).
#
# Der Leseschutz verglich den Pfad vorher mit expand_path, also ohne Umwege
# aufzuloesen. `/tmp/x/../geheim/f` enthaelt den geschuetzten Pfad woertlich nicht,
# liest ihn aber. Jetzt wird auf beiden Seiten _norm_path benutzt, das ../ ./ //
# lexikalisch kollabiert -- dieselbe Haerte, die der Selbstschutz schon hatte.
#
# Mit der Umstellung ist auch der rohe Zusatzvergleich (file_path.startswith)
# entfallen: Mit normalisierten Pfaden bringt er nichts und war die eine Stelle, an
# der ein Umweg noch vorbeikam.
#
# Rein lexikalisch, kein Dateisystemzugriff -- Symlinks bleiben out of scope
# (s. THREAT-MODEL). Reiner DRY-RUN: nur die Entscheidung wird geprueft, es wird
# nichts gelesen und nichts angelegt.
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

GEHEIM = "/tmp/guard-test-geheim"   # simuliert always_blocked_reads
NEBEN = "/tmp/guard-test-offen"     # unkritisch


def _make_rules() -> str:
    rules = json.loads(EXAMPLE_RULES.read_text(encoding="utf-8"))
    rules.setdefault("protected_reads", {})
    rules["protected_reads"]["always_blocked_reads"] = [GEHEIM]
    rules["protected_reads"]["always_allowed"] = []
    rules["protected_reads"]["require_override_1"] = []
    tf = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
    json.dump(rules, tf)
    tf.close()
    return tf.name


def _run(file_path: str, rules_path: str) -> int:
    with tempfile.TemporaryDirectory() as ov:
        payload = {
            "session_id": "read-traversal-test",
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": file_path},
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
    ("direkt",           f"{GEHEIM}/f",                        BLOCK),
    ("daneben",          f"{NEBEN}/f",                         ALLOW),
    # Enthaelt den geschuetzten Pfad woertlich NICHT, liest ihn aber:
    ("umweg-von-aussen", f"{NEBEN}/../guard-test-geheim/f",    BLOCK),
    ("punkt-segment",    f"{GEHEIM}/./f",                      BLOCK),
    ("doppelter-slash",  f"{GEHEIM}//f",                       BLOCK),
]


def run_all():
    rules = _make_rules()
    ergebnisse = []
    try:
        for cid, pfad, expected in CASES:
            rc = _run(pfad, rules)
            ergebnisse.append((cid, pfad, expected, rc, rc == expected))
    finally:
        try:
            os.unlink(rules)
        except OSError:
            pass
    return ergebnisse


try:
    import pytest

    _RULES = _make_rules()

    @pytest.mark.parametrize("cid,pfad,expected", CASES)
    def test_read_traversal(cid, pfad, expected):
        assert _run(pfad, _RULES) == expected, f"{cid}: {pfad!r}"

except ImportError:
    pass


if __name__ == "__main__":
    res = run_all()
    for cid, pfad, expected, rc, ok in res:
        tag = "PASS" if ok else "FAIL"
        exp = "allow" if expected == ALLOW else "block"
        got = "allow" if rc == ALLOW else ("block" if rc == BLOCK else f"rc={rc}")
        print(f"{tag}  {cid:18s} exp={exp:5s} got={got:5s}  {pfad}")
    passed = sum(1 for *_, ok in res if ok)
    print(f"\nLeseschutz-Umwege: {passed}/{len(res)} passed")
    raise SystemExit(0 if passed == len(res) else 1)
