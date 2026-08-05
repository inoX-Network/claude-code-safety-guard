# ============================================================================
# Auswahl bei MEHREREN gleichzeitig aktiven Overrides.
#
# Frueher gewann die HOECHSTE Stufe. Das ist ein Eskalationsweg ueber
# liegengebliebene Freigaben: Eine vergessene, noch nicht abgelaufene Stufe-2-Datei
# schlaegt still eine Stufe-1-Freigabe, die der Eigentuemer gerade absichtlich eng
# erteilt hat. Er liest "Stufe 1 aktiv" und bekommt Stufe 2.
#
# Jetzt gewinnt die ZULETZT ERTEILTE -- die, die er wirklich gemeint hat. Bei exakt
# gleichem Zeitstempel wird gar keine angewandt (fail-closed), statt zu raten.
#
# Reine Funktionspruefung von load_override() gegen ein temporaeres
# Override-Verzeichnis. Es wird nichts ausgefuehrt und nichts Echtes angefasst.
# ============================================================================
import importlib.util
import json
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
# GUARD_HOOK laesst diese Faelle gegen eine ANDERE Fassung laufen -- ohne das
# ist keine Gegenprobe moeglich, und ein Fall ohne Gegenprobe belegt nichts.
HOOK = Path(os.environ.get("GUARD_HOOK") or (REPO / "hooks" / "command-guard.py"))

_spec = importlib.util.spec_from_file_location("command_guard_under_test", HOOK)
cg = importlib.util.module_from_spec(_spec)
sys.modules["command_guard_under_test"] = cg
_spec.loader.exec_module(cg)


def _iso(**delta) -> str:
    return (datetime.now(timezone.utc) + timedelta(**delta)).isoformat()


def _schreibe(verzeichnis: str, name: str, **felder) -> None:
    daten = {"confirmed": True, "task": "test", "override_level": 1}
    daten.update(felder)
    Path(verzeichnis, name).write_text(json.dumps(daten), encoding="utf-8")


def _laden(verzeichnis: str):
    alt = os.environ.get("CLAUDE_SUDO_OVERRIDES_DIR")
    os.environ["CLAUDE_SUDO_OVERRIDES_DIR"] = verzeichnis
    try:
        return cg.load_override()
    finally:
        if alt is None:
            os.environ.pop("CLAUDE_SUDO_OVERRIDES_DIR", None)
        else:
            os.environ["CLAUDE_SUDO_OVERRIDES_DIR"] = alt


def test_frische_stufe_1_schlaegt_alte_stufe_2():
    """DIE TRAGENDE ZUSAGE: Eine liegengebliebene hoehere Stufe darf eine gerade
    erteilte engere NICHT ueberschreiben."""
    with tempfile.TemporaryDirectory() as d:
        _schreibe(d, "alt.json", override_level=2, task="vergessene Altfreigabe",
                  granted_at=_iso(hours=-6), expires_at=_iso(hours=+6))
        _schreibe(d, "neu.json", override_level=1, task="gerade erteilt, eng",
                  granted_at=_iso(minutes=-1), expires_at=_iso(minutes=+59))
        gewaehlt = _laden(d)
        assert gewaehlt is not None
        assert gewaehlt["override_level"] == 1, (
            "Die aeltere Stufe 2 hat gewonnen — das ist der Eskalationsweg, den "
            "diese Auswahl schliessen soll."
        )


def test_einzelne_freigabe_wird_unveraendert_genommen():
    with tempfile.TemporaryDirectory() as d:
        _schreibe(d, "eine.json", override_level=2, granted_at=_iso(minutes=-5),
                  expires_at=_iso(hours=+1))
        gewaehlt = _laden(d)
        assert gewaehlt is not None and gewaehlt["override_level"] == 2


def test_gleichstand_wendet_gar_nichts_an():
    """Bei identischem Zeitstempel wird nicht geraten, sondern fail-closed."""
    with tempfile.TemporaryDirectory() as d:
        gleich = _iso(minutes=-3)
        _schreibe(d, "a.json", override_level=1, granted_at=gleich,
                  expires_at=_iso(hours=+1))
        _schreibe(d, "b.json", override_level=2, granted_at=gleich,
                  expires_at=_iso(hours=+1))
        assert _laden(d) is None


def test_rueckfall_auf_expires_at_ohne_granted_at():
    """Aeltere Dateien kennen granted_at nicht. Dann entscheidet expires_at, das bei
    fester Laufzeit mit der Erteilung mitsteigt."""
    with tempfile.TemporaryDirectory() as d:
        _schreibe(d, "alt.json", override_level=2, task="alt, laeuft frueher ab",
                  expires_at=_iso(minutes=+10))
        _schreibe(d, "neu.json", override_level=1, task="neuer, laeuft spaeter ab",
                  expires_at=_iso(minutes=+90))
        gewaehlt = _laden(d)
        assert gewaehlt is not None and gewaehlt["override_level"] == 1


def test_deutscher_feldname_zaehlt_genauso():
    """Ein Freigabe-Skript darf den Erteilungszeitpunkt 'freigegeben_am' nennen.

    Wird nur 'granted_at' gelesen, faellt so eine Anlage still auf expires_at
    zurueck. Das bleibt fail-closed, ist aber die ungenauere Regel: Hier laufen
    beide Freigaben gleich lang, die aeltere hoehere Stufe wuerde also gewinnen —
    genau der Eskalationsweg, den diese Auswahl schliessen soll.
    """
    with tempfile.TemporaryDirectory() as d:
        laufzeit = _iso(hours=+6)
        _schreibe(d, "alt.json", override_level=2, task="vergessene Altfreigabe",
                  freigegeben_am=_iso(hours=-6), expires_at=laufzeit)
        _schreibe(d, "neu.json", override_level=1, task="gerade erteilt, eng",
                  freigegeben_am=_iso(minutes=-1), expires_at=laufzeit)
        gewaehlt = _laden(d)
        assert gewaehlt is not None
        assert gewaehlt["override_level"] == 1, (
            "Der deutsche Feldname wurde nicht gelesen — die Auswahl fiel auf "
            "expires_at zurueck und die alte Stufe 2 hat gewonnen."
        )


def test_gleichstand_auch_beim_deutschen_feldnamen():
    """Kein Raten, egal unter welchem Namen der Zeitstempel steht."""
    with tempfile.TemporaryDirectory() as d:
        gleich = _iso(minutes=-3)
        _schreibe(d, "a.json", override_level=1, freigegeben_am=gleich,
                  expires_at=_iso(hours=+1))
        _schreibe(d, "b.json", override_level=2, freigegeben_am=gleich,
                  expires_at=_iso(hours=+1))
        assert _laden(d) is None


def test_abgelaufene_zaehlt_nicht_mit():
    with tempfile.TemporaryDirectory() as d:
        _schreibe(d, "abgelaufen.json", override_level=3, granted_at=_iso(minutes=-1),
                  expires_at=_iso(minutes=-1))
        _schreibe(d, "gueltig.json", override_level=1, granted_at=_iso(minutes=-30),
                  expires_at=_iso(hours=+1))
        gewaehlt = _laden(d)
        assert gewaehlt is not None and gewaehlt["override_level"] == 1


if __name__ == "__main__":
    faelle = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    rot = 0
    for f in faelle:
        try:
            f()
            print(f"PASS  {f.__name__}")
        except AssertionError as e:
            rot += 1
            print(f"FAIL  {f.__name__}: {e}")
    print(f"\nOverride-Auswahl: {len(faelle) - rot}/{len(faelle)} passed")
    raise SystemExit(1 if rot else 0)
