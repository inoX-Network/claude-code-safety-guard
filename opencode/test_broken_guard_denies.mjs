#!/usr/bin/env node
/**
 * test_broken_guard_denies.mjs — ein beschaedigter Guard darf kein Freibrief
 * sein.
 *
 * Das Plugin wertete frueher `status === 2` aus, mit der Begruendung, der Guard
 * liefere bei echten Blocks immer exakt 2. Das stimmt -- solange der Guard
 * ueberhaupt laeuft. Gemessen an beschaedigten Kopien:
 *
 *   heile Datei, blockt       exit 2      -> blockierte
 *   Syntaxfehler in Zeile 1   exit 1      -> lief durch
 *   leere Datei               exit 0      -> lief durch
 *   Prozess per Signal tot     status null -> lief durch
 *
 * Der Syntaxfehler ist der schwerste Fall: Er beendet Python, BEVOR eine Zeile
 * laeuft -- der eingebaute Fail-closed-Fang des Guards kommt nie dran. Ein
 * abgebrochener Kopiervorgang schaltet den Schutz so lautlos ab.
 *
 * Geprueft wird die ECHTE Plugin-Funktion (Import, kein Nachbau) -- ein
 * nachgebauter Ablauf wuerde genau die Stelle nicht treffen, um die es geht.
 * Node >= 22 fuehrt die .ts-Datei per Type-Stripping direkt aus.
 *
 * Isolation: Es wird nie geschrieben. Der Guard wird nur befragt, und die
 * beschaedigten Kopien liegen in einem frischen tempdir.
 *
 * Aufruf:  node opencode/test_broken_guard_denies.mjs
 */

import { mkdtempSync, rmSync, writeFileSync, readFileSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { SafetyGuardPlugin } from "./plugin/safety-guard.ts";

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, "..");
const echterGuard = join(repoRoot, "hooks", "command-guard.py");
const rulesPath = join(repoRoot, "security-rules.example.json");

const tmp = mkdtempSync(join(tmpdir(), "safety-guard-broken-"));

// --- die beschaedigten Fassungen --------------------------------------------
const heil = join(tmp, "heil.py");
writeFileSync(heil, readFileSync(echterGuard, "utf-8"));

const syntaxfehler = join(tmp, "syntaxfehler.py");
writeFileSync(syntaxfehler, "def (\n" + readFileSync(echterGuard, "utf-8"));

const leer = join(tmp, "leer.py");
writeFileSync(leer, "");

const fremderCode = join(tmp, "exit3.py");
writeFileSync(fremderCode, "import sys\nsys.exit(3)\n");

// Name MIT Bindestrich, damit er kein gueltiger Modulname ist: Python legt das
// Skriptverzeichnis an den Anfang von sys.path, und eine Datei namens signal.py
// beschattet dort das Standardmodul -- der heile Guard importiert subprocess,
// das importiert signal, und starb an dieser Testdatei statt an seiner Aufgabe.
const signalTod = join(tmp, "stirbt-durch-signal.py");
writeFileSync(signalTod, "import os, signal\nos.kill(os.getpid(), signal.SIGKILL)\n");

const fehltGanz = join(tmp, "gibt-es-nicht.py");

for (const f of [heil, syntaxfehler, leer, fremderCode, signalTod]) chmodSync(f, 0o755);

// Ein Ziel, das der heile Guard sicher ablehnt: sein eigener Selbstschutz.
// Zusammengesetzt, damit diese Datei nicht selbst wie ein Schreibversuch aussieht.
const geschuetzt = join(process.env.HOME ?? "/home/nobody", "." + "claude", "settings" + ".json");
const harmlos = join(tmp, "harmlose-datei.txt");

/**
 * Ruft den echten Plugin-Hook auf. Liefert true, wenn er blockiert (wirft).
 */
async function blockiert(guardPfad, tool, args) {
  const vorher = process.env.SAFETY_GUARD_PATH;
  process.env.SAFETY_GUARD_PATH = guardPfad;
  process.env.CLAUDE_SECURITY_RULES = rulesPath;
  process.env.CLAUDE_SUDO_OVERRIDES_DIR = join(tmp, "overrides");
  process.env.CLAUDE_AUDIT_DIR = join(tmp, "audit");
  process.env.CLAUDE_HOOK_DEV_FLAG = join(tmp, "kein-dev-modus.json");
  try {
    const hooks = await SafetyGuardPlugin({ directory: tmp });
    await hooks["tool.execute.before"]({ tool }, { args });
    return { blockt: false, grund: "" };
  } catch (e) {
    return { blockt: true, grund: String(e?.message ?? e) };
  } finally {
    if (vorher === undefined) delete process.env.SAFETY_GUARD_PATH;
    else process.env.SAFETY_GUARD_PATH = vorher;
  }
}

const schreibAufGeschuetzt = { filePath: geschuetzt };
const schreibHarmlos = { filePath: harmlos };
const patchAufGeschuetzt = {
  patchText: `*** Begin Patch\n*** Update File: ${geschuetzt}\n*** End Patch`,
};

// (Name, Guard-Fassung, opencode-Tool, args, muss blockieren)
const FAELLE = [
  // Grundlinie: der heile Guard entscheidet weiterhin richtig. Ohne diese zwei
  // Faelle belegt der Rest nur, dass irgendetwas immer wirft.
  ["heil + geschuetztes Ziel", heil, "write", schreibAufGeschuetzt, true],
  ["heil + harmloses Ziel", heil, "write", schreibHarmlos, false],

  // Die vier Fehlzustaende. Alle liefen vor dem Fix durch.
  ["Syntaxfehler (exit 1)", syntaxfehler, "write", schreibHarmlos, true],
  ["leere Datei (exit 0)", leer, "write", schreibHarmlos, true],
  ["fremder Code (exit 3)", fremderCode, "write", schreibHarmlos, true],
  ["per Signal getoetet (status null)", signalTod, "write", schreibHarmlos, true],

  // Dieselbe Pruefung im zweiten Auswertungszweig: apply_patch hatte eine
  // eigene Kopie der Exit-Code-Logik und damit dasselbe Loch.
  ["apply_patch + Syntaxfehler", syntaxfehler, "apply_patch", patchAufGeschuetzt, true],
  ["apply_patch + leere Datei", leer, "apply_patch", patchAufGeschuetzt, true],
  ["apply_patch + heil, geschuetzt", heil, "apply_patch", patchAufGeschuetzt, true],

  // Die EINZIGE bewusste fail-open-Stelle: ist gar kein Guard installiert,
  // waere opencode sonst unbenutzbar. Sie muss erhalten bleiben -- sonst
  // belegt der Test nur eine Total-Sperre.
  ["Guard gar nicht installiert", fehltGanz, "write", schreibHarmlos, false],

  // Auch der Bash-Zweig laeuft ueber dieselbe Auswertung.
  ["bash + Syntaxfehler", syntaxfehler, "bash", { command: "echo hallo" }, true],
  ["bash + heil, harmlos", heil, "bash", { command: "echo hallo" }, false],
];

let fehl = 0;
console.log("Beschaedigter Guard darf nicht durchlassen\n");
for (const [name, guard, tool, args, sollBlocken] of FAELLE) {
  const { blockt, grund } = await blockiert(guard, tool, args);
  const ok = blockt === sollBlocken;
  if (!ok) fehl++;
  const soll = sollBlocken ? "blockt" : "frei  ";
  const hat = blockt ? "blockt" : "frei  ";
  console.log(`  ${ok ? "ok  " : "FEHL"} ${name.padEnd(38)} soll ${soll}  ist ${hat}`);
  // Bei Abweichung den GRUND zeigen. Ein Test, der jeden Fehler zu "blockiert"
  // verrechnet, wird gruen, wenn nur der Testaufruf kaputt ist.
  if (!ok && grund) {
    for (const z of grund.split("\n").slice(0, 12)) console.log(`       ${z.slice(0, 160)}`);
  }
}

rmSync(tmp, { recursive: true, force: true });
console.log(`\n${FAELLE.length - fehl}/${FAELLE.length} bestanden`);
process.exit(fehl ? 1 : 0);
