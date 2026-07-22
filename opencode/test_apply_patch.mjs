#!/usr/bin/env node
/**
 * test_apply_patch.mjs — prueft das Schliessen der apply_patch-Luecke.
 *
 * Hintergrund: opencodes Multi-Datei-Patch-Tool `apply_patch` liefert keinen
 * einzelnen filePath, sondern einen Diff ueber n Dateien. Es war deshalb frueher
 * bewusst NICHT gegated. Solange opencode in der bubblewrap-Sandbox lief, hat die
 * Sandbox das aufgefangen. Laeuft opencode ungesandboxt auf dem Host (Guard als
 * Autoritaet, wie unter Claude Code), war apply_patch ein Schreibkanal ohne Bremse.
 *
 * Der Test hat zwei Ebenen:
 *   1. PARSER — prueft die ECHTE patchZielPfade() aus safety-guard.ts (Import,
 *      kein Nachbau). Kern: relative Patch-Pfade muessen ABSOLUT aufgeloest
 *      werden, sonst kann der Guard "../../.claude/settings.json" nicht gegen
 *      seine Self-Protect-Liste matchen und wuerde durchwinken.
 *   2. GUARD — schickt die aufgeloesten Pfade durch das echte command-guard.py
 *      und prueft den Exit-Code (End-to-End).
 *
 * Node >= 22 fuehrt die .ts-Datei per Type-Stripping direkt aus — kein Build noetig.
 *
 * Isolation (damit der Test nichts am echten System anfasst):
 *   - CLAUDE_SECURITY_RULES  -> security-rules.example.json des Repos
 *   - CLAUDE_SUDO_OVERRIDES_DIR / CLAUDE_AUDIT_DIR -> frisches tempdir
 *   - CLAUDE_HOOK_DEV_FLAG    -> nicht existierender Pfad (Dev-Modus aus)
 * Geschrieben wird NIE — der Guard wird nur befragt, der Patch nie angewendet.
 *
 * Aufruf:  node opencode/test_apply_patch.mjs
 */

import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { patchZielPfade } from "./plugin/safety-guard.ts";

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, "..");
const guardPath = join(repoRoot, "hooks", "command-guard.py");
const rulesPath = join(repoRoot, "security-rules.example.json");

// Fiktives Projektverzeichnis — zwei Ebenen unter dem Home, damit "../../"
// im Traversal-Testfall exakt im Home landet.
const PROJEKT = join(homedir(), "Projekte", "testprojekt");

const tmp = mkdtempSync(join(tmpdir(), "safety-guard-patch-"));
const env = {
  ...process.env,
  CLAUDE_SECURITY_RULES: rulesPath,
  CLAUDE_SUDO_OVERRIDES_DIR: join(tmp, "overrides"),
  CLAUDE_AUDIT_DIR: join(tmp, "audit"),
  CLAUDE_HOOK_DEV_FLAG: join(tmp, "does-not-exist.json"),
};

function patch(...zeilen) {
  return ["*** Begin Patch", ...zeilen, "*** End Patch"].join("\n");
}

// Ruft den Guard fuer EINEN Pfad als Write auf (exakt was das Plugin tut).
function guardFuerPfad(pfad) {
  const res = spawnSync("python3", [guardPath], {
    input: JSON.stringify({
      tool_name: "Write",
      tool_input: { file_path: pfad },
    }),
    encoding: "utf-8",
    env,
  });
  return res.status;
}

// Bildet die Plugin-Entscheidung nach: JEDER Ziel-Pfad muss durch. Einer blockt
// => der ganze Patch blockt (ein Patch ist atomar).
function patchWirdBlockiert(patchText) {
  const pfade = patchZielPfade(patchText, PROJEKT);
  if (pfade.length === 0) return "FAIL_CLOSED"; // Plugin wirft hier
  return pfade.some((p) => guardFuerPfad(p) === 2) ? "BLOCK" : "ERLAUBT";
}

let fehler = 0;
const pruefe = (name, ist, soll) => {
  const ok = JSON.stringify(ist) === JSON.stringify(soll);
  if (!ok) fehler++;
  console.log(`  ${ok ? "OK  " : "FAIL"}  ${name}`);
  if (!ok) {
    console.log(`        erwartet: ${JSON.stringify(soll)}`);
    console.log(`        bekommen: ${JSON.stringify(ist)}`);
  }
};

console.log(`Guard:   ${guardPath}`);
console.log(`Rules:   ${rulesPath}`);
console.log(`Projekt: ${PROJEKT}`);
console.log("");

// ---------------------------------------------------------------------------
console.log("EBENE 1 — PARSER (patchZielPfade aus safety-guard.ts)");
// ---------------------------------------------------------------------------

pruefe(
  "Update File wird relativ zum Projekt aufgeloest",
  patchZielPfade(patch("*** Update File: src/foo.ts"), PROJEKT),
  [join(PROJEKT, "src/foo.ts")],
);

pruefe(
  "Add File wird erfasst",
  patchZielPfade(patch("*** Add File: neu.ts"), PROJEKT),
  [join(PROJEKT, "neu.ts")],
);

pruefe(
  "Delete File wird erfasst (Loeschen ist auch ein Schreibzugriff)",
  patchZielPfade(patch("*** Delete File: alt.ts"), PROJEKT),
  [join(PROJEKT, "alt.ts")],
);

pruefe(
  "Move to wird erfasst (Umbenennungs-ZIEL, sonst uebersehen)",
  patchZielPfade(
    patch("*** Update File: a.ts", "*** Move to: b.ts"),
    PROJEKT,
  ),
  [join(PROJEKT, "a.ts"), join(PROJEKT, "b.ts")],
);

// DER KERNFALL: ohne absolute Aufloesung saehe der Guard nur den String
// "../../.claude/settings.json" und koennte ihn nicht gegen SELF_PROTECT matchen.
pruefe(
  "KERNFALL Traversal: ../../.claude/settings.json wird absolut aufgeloest",
  patchZielPfade(patch("*** Update File: ../../.claude/settings.json"), PROJEKT),
  [join(homedir(), ".claude", "settings.json")],
);

pruefe(
  "Absoluter Pfad bleibt absolut",
  patchZielPfade(patch("*** Update File: /etc/passwd"), PROJEKT),
  ["/etc/passwd"],
);

pruefe(
  "Mehrere Dateien werden alle erfasst",
  patchZielPfade(
    patch("*** Update File: a.ts", "*** Add File: b.ts", "*** Delete File: c.ts"),
    PROJEKT,
  ),
  [join(PROJEKT, "a.ts"), join(PROJEKT, "b.ts"), join(PROJEKT, "c.ts")],
);

pruefe(
  "Doppelter Pfad wird dedupliziert",
  patchZielPfade(
    patch("*** Update File: a.ts", "*** Update File: a.ts"),
    PROJEKT,
  ),
  [join(PROJEKT, "a.ts")],
);

pruefe(
  "Patch ohne erkennbares Ziel liefert nichts (Plugin blockt dann fail-closed)",
  patchZielPfade(patch("irgendwas ohne Direktive"), PROJEKT),
  [],
);

// ---------------------------------------------------------------------------
console.log("");
console.log("EBENE 2 — GUARD (aufgeloeste Pfade durch command-guard.py)");
// ---------------------------------------------------------------------------

pruefe(
  "KERNFALL: Traversal auf ~/.claude/settings.json wird BLOCKIERT",
  patchWirdBlockiert(patch("*** Update File: ../../.claude/settings.json")),
  "BLOCK",
);

pruefe(
  "Traversal auf ~/.claude/hooks (der Guard selbst) wird BLOCKIERT",
  patchWirdBlockiert(patch("*** Add File: ../../.claude/hooks/boese.py")),
  "BLOCK",
);

pruefe(
  "Schreiben auf /etc/passwd wird BLOCKIERT",
  patchWirdBlockiert(patch("*** Update File: /etc/passwd")),
  "BLOCK",
);

pruefe(
  "Schreiben in ~/.ssh wird BLOCKIERT",
  patchWirdBlockiert(patch("*** Add File: ../../.ssh/authorized_keys")),
  "BLOCK",
);

pruefe(
  "Normale Projektdatei ist ERLAUBT (kein Fehlalarm)",
  patchWirdBlockiert(patch("*** Update File: src/foo.ts")),
  "ERLAUBT",
);

// Atomaritaet: EIN boeser Pfad unter vielen harmlosen muss den ganzen Patch kippen.
// Das ist der realistische Angriff — der Schadpfad wird zwischen echte Aenderungen
// gestreut, damit er beim Drueberschauen nicht auffaellt.
pruefe(
  "Ein boeser Pfad zwischen harmlosen kippt den GANZEN Patch",
  patchWirdBlockiert(
    patch(
      "*** Update File: src/a.ts",
      "*** Update File: src/b.ts",
      "*** Add File: ../../.claude/hooks/boese.py",
      "*** Update File: src/c.ts",
    ),
  ),
  "BLOCK",
);

pruefe(
  "Patch ohne lesbares Ziel wird fail-closed behandelt",
  patchWirdBlockiert(patch("kaputtes Format")),
  "FAIL_CLOSED",
);

rmSync(tmp, { recursive: true, force: true });

console.log("");
if (fehler === 0) {
  console.log("Ergebnis: ALLE apply_patch-Tests bestanden.");
  process.exit(0);
} else {
  console.log(`Ergebnis: ${fehler} Test(s) FEHLGESCHLAGEN.`);
  process.exit(1);
}
