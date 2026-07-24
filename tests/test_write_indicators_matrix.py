# ============================================================================
# Matrix-Suite zur WRITE_INDICATORS-/Symlink-Lücke.
# Basis: projekte/0050-safety-guard/BEFUND-guard-scope-symlink-2026-07-24.md §2.
#
# Reiner DRY-RUN: Der Hook wird via stdin-JSON aufgerufen und NUR die Entscheidung
# (Exit 0 = allow, Exit 2 = block) geprüft. Es wird NICHTS ausgeführt, keine Datei
# gelöscht. Schutzzone ist ein WEGWERF-Pfad (/tmp/guard-test-protected) via
# CLAUDE_SECURITY_RULES — echte Schutzpfade (/etc, ~/.ssh) werden nie berührt.
#
# 11 Befehlsvarianten x 4 Kontexte = 44 Zellen. Erwartungen = NACH dem Klasse-1-Fix:
# die 4 Spalte-2-Zellen unlink/find/shred/rsync sind jetzt BLOCK (vorher ⚠L-allow),
# rm/rmr/rmdir/mv/truncate/redirect auf Zone weiterhin BLOCK, unkritische Zone
# (Spalte 1) und Symlink-Spalten 3/4 bleiben ALLOW (Symlink bewusst out of scope).
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

# Wegwerf-Zone (nur in der Regeldatei; es wird real nie hierhin geschrieben).
ZONE = "/tmp/guard-test-protected"      # simulierter protected_path
SAFE = "/tmp/guard-test-unkritisch"     # unkritische Zone
LINK = SAFE + "/link"                   # Symlink (unkritisch) -> Ziel in ZONE
DIRL = SAFE + "/dirlink"                # Verzeichnis-Symlink -> ZONE


def _make_rules() -> str:
    """Beispiel-Regeln laden, blocked_paths_write auf die Wegwerf-Zone setzen."""
    rules = json.loads(EXAMPLE_RULES.read_text(encoding="utf-8"))
    rules["blocked_paths_write"] = [ZONE]
    tf = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
    json.dump(rules, tf)
    tf.close()
    return tf.name


def _run(command: str, rules_path: str) -> int:
    """Hook als PreToolUse-Dry-run aufrufen, Exit-Code zurückgeben (0=allow, 2=block)."""
    with tempfile.TemporaryDirectory() as ov:
        payload = {
            "session_id": "matrix-test",
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


# (case_id, command, expected_returncode)  — expected = nach Klasse-1-Fix.
CASES = [
    # ---- Spalte 1: unkritische Zone -> alles allow (korrekt/gewollt) ----
    ("s1_rm",       f"rm {SAFE}/f",                 ALLOW),
    ("s1_rmr",      f"rm -r {SAFE}/d",              ALLOW),
    ("s1_rmdir",    f"rmdir {SAFE}/d",              ALLOW),
    ("s1_unlink",   f"unlink {SAFE}/f",             ALLOW),
    ("s1_find",     f"find {SAFE} -delete",         ALLOW),
    ("s1_mv",       f"mv {SAFE}/f /tmp/",           ALLOW),
    ("s1_shred",    f"shred {SAFE}/f",              ALLOW),
    ("s1_truncate", f"truncate -s0 {SAFE}/f",       ALLOW),
    ("s1_redirect", f"> {SAFE}/f",                  ALLOW),
    ("s1_rsync",    f"rsync --delete /tmp/src/ {SAFE}/", ALLOW),
    ("s1_gitclean", "git clean -fdx",               ALLOW),

    # ---- Spalte 2: protected_path direkt ----
    ("s2_rm",       f"rm {ZONE}/f",                 BLOCK),   # WRITE_INDICATOR rm + Zone
    ("s2_rmr",      f"rm -r {ZONE}/d",              BLOCK),
    ("s2_rmdir",    f"rmdir {ZONE}/d",              BLOCK),
    ("s2_unlink",   f"unlink {ZONE}/f",             BLOCK),   # KLASSE-1: nach Fix geblockt (war ⚠L allow)
    ("s2_find",     f"find {ZONE} -delete",         BLOCK),   # KLASSE-1: nach Fix geblockt (war ⚠L allow)
    ("s2_mv",       f"mv {ZONE}/f /tmp/",           BLOCK),
    ("s2_shred",    f"shred {ZONE}/f",              BLOCK),   # KLASSE-1: nach Fix geblockt (war ⚠L allow)
    ("s2_truncate", f"truncate -s0 {ZONE}/f",       BLOCK),
    ("s2_redirect", f"> {ZONE}/f",                  BLOCK),
    ("s2_rsync",    f"rsync --delete /tmp/src/ {ZONE}/", BLOCK),  # KLASSE-1: nach Fix geblockt (war ⚠L allow)
    ("s2_gitclean", "git clean -fdx",               ALLOW),   # kein Zone-Pfad im Befehl -> bleibt allow

    # ---- Spalte 3: Symlink (unkritisch) -> Ziel in Zone. Guard löst NICHT auf ----
    #      -> lexikalisch unkritischer Pfad -> allow (Known Limitation, bleibt auch nach Fix)
    ("s3_rm",       f"rm {LINK}",                   ALLOW),
    ("s3_rmr",      f"rm -r {LINK}",                ALLOW),
    ("s3_rmdir",    f"rmdir {LINK}",                ALLOW),
    ("s3_unlink",   f"unlink {LINK}",               ALLOW),
    ("s3_find",     f"find {LINK} -delete",         ALLOW),
    ("s3_mv",       f"mv {LINK} /tmp/",             ALLOW),
    ("s3_shred",    f"shred {LINK}",                ALLOW),
    ("s3_truncate", f"truncate -s0 {LINK}",         ALLOW),
    ("s3_redirect", f"> {LINK}",                    ALLOW),
    ("s3_rsync",    f"rsync --delete /tmp/src/ {LINK}/", ALLOW),
    ("s3_gitclean", "git clean -fdx",               ALLOW),

    # ---- Spalte 4: Verzeichnis-Symlink -> Zone, mit trailing slash ----
    #      -> lexikalisch unkritischer Pfad -> allow (Known Limitation, bleibt auch nach Fix)
    ("s4_rm",       f"rm {DIRL}/",                  ALLOW),
    ("s4_rmr",      f"rm -r {DIRL}/",               ALLOW),
    ("s4_rmdir",    f"rmdir {DIRL}/",               ALLOW),
    ("s4_unlink",   f"unlink {DIRL}/",              ALLOW),
    ("s4_find",     f"find {DIRL}/ -delete",        ALLOW),
    ("s4_mv",       f"mv {DIRL}/ /tmp/",            ALLOW),
    ("s4_shred",    f"shred {DIRL}/x",              ALLOW),
    ("s4_truncate", f"truncate -s0 {DIRL}/x",       ALLOW),
    ("s4_redirect", f"> {DIRL}/x",                  ALLOW),
    ("s4_rsync",    f"rsync --delete /tmp/src/ {DIRL}/", ALLOW),
    ("s4_gitclean", "git clean -fdx",               ALLOW),
]


def run_all():
    rules = _make_rules()
    results = []
    try:
        for cid, cmd, expected in CASES:
            rc = _run(cmd, rules)
            ok = rc == expected
            results.append((cid, cmd, expected, rc, ok))
    finally:
        os.unlink(rules)
    return results


# --- pytest-Einstieg (ein Test pro Zelle) ---
try:
    import pytest

    _RULES = _make_rules()

    def teardown_module():
        try:
            os.unlink(_RULES)
        except OSError:
            pass

    @pytest.mark.parametrize("cid,cmd,expected", [(c[0], c[1], c[2]) for c in CASES])
    def test_write_indicators_matrix(cid, cmd, expected):
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
        print(f"{tag}  {cid:14s} exp={exp:5s} got={got:5s}  {cmd}")
    passed = sum(1 for *_, ok in res if ok)
    print(f"\nMatrix: {passed}/{len(res)} passed")
    raise SystemExit(0 if passed == len(res) else 1)
