/**
 * safety-guard.ts — opencode-Port des command-guard.py PreToolUse-Gates.
 *
 * Ziel: Derselbe deterministische Python-Guard, der unter Claude Code Tool-Calls
 * blockiert, soll auch unter opencode (https://github.com/sst/opencode) greifen.
 *
 * Funktionsweise:
 *   - opencode feuert das Event `tool.execute.before` VOR jedem Tool-Call.
 *   - Wir mappen opencodes Tool-Name + Argumente auf das command-guard-JSON
 *     (Felder tool_name / tool_input), rufen command-guard.py per child_process
 *     mit diesem JSON auf stdin auf und werten den Exit-Code aus.
 *   - Exit 2 (Guard blockiert) => wir `throw` => opencode bricht den Tool-Call ab.
 *   - Exit 0 (Guard erlaubt) => wir tun nichts => Tool-Call laeuft normal.
 *
 * EHRLICHKEIT / gegen die installierte opencode-Version zu verifizieren:
 *   - Die Signatur `(input, output)` und die Feldnamen (`input.tool`,
 *     `output.args.command`, `output.args.filePath`) sind aus den opencode-Docs
 *     hergeleitet, NICHT gegen den `@opencode-ai/plugin`-TypeScript-Typ verifiziert.
 *     Pruefe das gegen deine opencode-Version (siehe opencode/README.md).
 *   - `input.sessionID` / `input.callID` sind nicht eindeutig dokumentiert —
 *     wir behandeln sie defensiv (optional chaining) und verlassen uns NICHT
 *     auf sie.
 *
 * Keine externen npm-Deps. `node:child_process` + `node:os`/`node:path` sind
 * unter Bun (opencodes Runtime) und Node verfuegbar.
 */

import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { isAbsolute, join, resolve } from "node:path";

// ---------------------------------------------------------------------------
// Konfiguration
// ---------------------------------------------------------------------------

// Pfad zum Python-Guard. Per ENV ueberschreibbar, sonst der Claude-Code-Default.
function resolveGuardPath(): string {
  const fromEnv = process.env.SAFETY_GUARD_PATH;
  if (fromEnv && fromEnv.trim() !== "") return fromEnv;
  return join(homedir(), ".claude", "hooks", "command-guard.py");
}

// Mapping opencode-Tool -> command-guard tool_name + Argument-Schluessel.
// Wichtig: NUR Tools die der Guard tatsaechlich kennt werden gegated. Alle
// anderen (z.B. "list", "glob", "grep", "webfetch", "todoread", MCP-Tools)
// werden BEWUSST durchgelassen — der Guard hat dafuer keine Regeln, und ein
// pauschales Blocken unbekannter Tools wuerde jede Session unbrauchbar machen.
// (Der Python-Guard kennt zwar mcp__-Tools, opencode liefert MCP-Calls aber
//  nicht zwingend im selben Namensschema — daher hier konservativ nicht gemappt.)
type GuardMapping = {
  toolName: "Bash" | "Read" | "Write" | "Edit";
  // Welcher opencode-arg-Schluessel die relevante Nutzlast traegt.
  argKey: "command" | "filePath";
  // Unter welchem Schluessel der Guard die Nutzlast in tool_input erwartet.
  inputKey: "command" | "file_path";
};

const TOOL_MAP: Record<string, GuardMapping> = {
  // bash -> Bash, command -> tool_input.command
  bash: { toolName: "Bash", argKey: "command", inputKey: "command" },
  // read -> Read, filePath -> tool_input.file_path (Credential-/.env-Schutz)
  read: { toolName: "Read", argKey: "filePath", inputKey: "file_path" },
  // write -> Write, filePath -> tool_input.file_path (Self-Protect/Pfad-Schutz)
  write: { toolName: "Write", argKey: "filePath", inputKey: "file_path" },
  // edit -> Edit, filePath -> tool_input.file_path
  edit: { toolName: "Edit", argKey: "filePath", inputKey: "file_path" },
  // apply_patch wird NICHT hier gemappt, sondern gesondert behandelt (s.u.):
  // Es traegt keinen einzelnen filePath, sondern einen Diff ueber n Dateien.
};

// --- apply_patch ------------------------------------------------------------
//
// opencodes Multi-Datei-Patch-Tool. Es liefert KEINEN filePath, sondern
// "patchText" im OpenAI-apply_patch-Format:
//
//     *** Begin Patch
//     *** Update File: src/foo.ts
//     *** Move to: src/bar.ts
//     *** Add File: neu.ts
//     *** Delete File: alt.ts
//     *** End Patch
//
// Frueher war apply_patch bewusst NICHT gegated (kein sauberes 1:1-Mapping auf
// den Guard, der genau EINEN file_path erwartet). Das war eine echte Luecke:
// Solange opencode in der bubblewrap-Sandbox lief, hat die Sandbox sie
// aufgefangen. Laeuft opencode ungesandboxt auf dem Host (Guard-als-Autoritaet,
// wie unter Claude Code), war apply_patch ein Schreibkanal voellig OHNE Bremse.
//
// Jetzt: Wir zerlegen den Patch in seine Ziel-Pfade und schicken JEDEN einzeln
// als Write durch den Guard. Ein einziger blockierter Pfad blockt den ganzen
// Patch (ein Patch ist atomar — teilweise anwenden gaebe es nicht).
//
// SICHERHEITSKERN — absolute Aufloesung: Die Pfade im Patch sind RELATIV zum
// Arbeitsverzeichnis. Wuerden wir "../../.claude/settings.json" unaufgeloest an
// den Guard geben, koennte der es gegen seine Self-Protect-Pfade nicht matchen
// und wuerde durchwinken. Deshalb wird jeder Pfad gegen das Projektverzeichnis
// absolut aufgeloest, BEVOR der Guard ihn sieht. Das ist der Traversal-Schutz.

// Erfasst die drei Direktiven, die eine Datei als Ziel benennen.
const PATCH_ZIEL_REGEX = /^\*\*\* (?:Add|Delete|Update) File:[ \t]*(.+?)[ \t]*$/gm;
// "Move to:" benennt das Umbenennungs-ZIEL — ebenfalls ein Schreibziel.
const PATCH_MOVE_REGEX = /^\*\*\* Move to:[ \t]*(.+?)[ \t]*$/gm;

// Zieht alle Schreib-Ziele aus einem Patch und loest sie absolut auf.
// Exportiert, damit opencode/test_apply_patch.mjs die ECHTE Funktion prueft
// statt die Logik im Test nachzubauen (Nachbauten driften — siehe der frueher
// verwaiste "patch"-Eintrag in test_bridge.mjs).
export function patchZielPfade(patchText: string, arbeitsverzeichnis: string): string[] {
  const gefunden = new Set<string>();

  for (const regex of [PATCH_ZIEL_REGEX, PATCH_MOVE_REGEX]) {
    regex.lastIndex = 0; // /g-Regex ist zustandsbehaftet — vor jedem Lauf zuruecksetzen
    let treffer: RegExpExecArray | null;
    while ((treffer = regex.exec(patchText)) !== null) {
      const roh = treffer[1]?.trim();
      if (!roh) continue;
      // Absolut aufloesen: relative Pfade (inkl. ../-Traversal) gegen das
      // Projektverzeichnis, absolute Pfade bleiben wie sie sind.
      gefunden.add(isAbsolute(roh) ? resolve(roh) : resolve(arbeitsverzeichnis, roh));
    }
  }

  return [...gefunden];
}

// Damit die "Guard nicht installiert"-Warnung nur EINMAL pro Prozess erscheint.
let warnedMissingGuard = false;

// Ruft command-guard.py mit einem tool_input auf und liefert Exit-Code + stderr.
function rufeGuard(
  guardPath: string,
  toolName: string,
  inputKey: string,
  payload: string,
  sessionID?: string,
): { status: number | null; stderr: string; error?: Error } {
  const guardInput: Record<string, unknown> = {
    tool_name: toolName,
    tool_input: { [inputKey]: payload },
  };
  // session_id defensiv mitgeben, falls vorhanden (Override-Session-Binding).
  if (sessionID) guardInput.session_id = sessionID;
  // agent_id liefert opencode hier nicht zuverlaessig -> bewusst weggelassen.
  // Ohne agent_id behandelt der Guard den Call als Hauptsession (Stufe 0),
  // was die sichere Default-Annahme ist.

  const result = spawnSync("python3", [guardPath], {
    input: JSON.stringify(guardInput),
    encoding: "utf-8",
  });

  return {
    status: result.status,
    stderr: (result.stderr || "").trim(),
    error: result.error ?? undefined,
  };
}

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------

// opencode entdeckt Plugins als BENANNTE Exports (kein Default-Export; verifiziert
// gegen @opencode-ai/plugin 1.17.7). Die Plugin-Funktion erhaelt einen Kontext
// (project, client, $, directory, worktree) — wir brauchen daraus `directory`, um
// die relativen apply_patch-Pfade absolut aufloesen zu koennen.
// Typ laut Package: (input, options?) => Promise<Hooks>.
export const SafetyGuardPlugin = async (ctx: unknown) => {
  const kontext = (ctx ?? {}) as { directory?: string; worktree?: string };
  // Fallback-Kette: directory -> worktree -> cwd. Ein falsches Arbeitsverzeichnis
  // wuerde relative Patch-Pfade falsch aufloesen, deshalb lieber cwd als nichts.
  const arbeitsverzeichnis =
    kontext.directory || kontext.worktree || process.cwd();

  return {
    "tool.execute.before": async (input: unknown, output: unknown) => {
      // Defensives Auslesen — die exakte Form ist nicht gegen den Typ verifiziert.
      const inp = (input ?? {}) as {
        tool?: string;
        sessionID?: string;
        callID?: string;
      };
      const out = (output ?? {}) as {
        args?: Record<string, unknown>;
      };

      const toolName = inp.tool;
      if (!toolName) return; // ohne Tool-Namen koennen wir nichts mappen -> durchlassen

      const args = out.args ?? {};
      const guardPath = resolveGuardPath();

      // Fail-OPEN nur fuer "Guard nicht installiert": Wuerden wir hier blocken,
      // waere opencode ohne installierten Guard komplett unbenutzbar. Das ist
      // die EINZIGE bewusste fail-open-Stelle — der Guard selbst ist fail-closed.
      if (!existsSync(guardPath)) {
        if (!warnedMissingGuard) {
          warnedMissingGuard = true;
          process.stderr.write(
            `[safety-guard] WARNUNG: command-guard.py nicht gefunden unter ` +
              `"${guardPath}". Tool-Calls werden NICHT geprueft. ` +
              `Setze SAFETY_GUARD_PATH korrekt, um den Schutz zu aktivieren.\n`,
          );
        }
        return;
      }

      // --- Sonderfall apply_patch: n Ziel-Pfade, jeder einzeln durch den Guard ---
      if (toolName === "apply_patch") {
        const patchText = args.patchText;
        if (typeof patchText !== "string" || patchText.trim() === "") {
          // Kein Patch-Inhalt -> nichts zu schreiben, nichts zu pruefen.
          return;
        }

        const zielPfade = patchZielPfade(patchText, arbeitsverzeichnis);

        // FAIL-CLOSED: Es liegt ein Patch vor, aber wir erkennen kein einziges
        // Ziel. Dann verstehen wir das Format nicht — und was wir nicht verstehen,
        // koennen wir nicht pruefen. Durchlassen waere hier genau das Loch, das
        // dieser Zweig schliessen soll.
        if (zielPfade.length === 0) {
          throw new Error(
            "[safety-guard] apply_patch: Kein Ziel-Pfad im Patch erkennbar " +
              "(erwartet: '*** Add/Update/Delete File:' oder '*** Move to:'). " +
              "Der Patch wurde vorsorglich blockiert, weil ein nicht lesbarer " +
              "Patch nicht geprüft werden kann.",
          );
        }

        for (const pfad of zielPfade) {
          const r = rufeGuard(guardPath, "Write", "file_path", pfad, inp.sessionID);

          if (r.error) {
            throw new Error(
              `[safety-guard] Konnte command-guard.py nicht ausführen: ` +
                `${r.error.message}. apply_patch vorsorglich blockiert. ` +
                `(python3 im PATH? Guard-Pfad korrekt?)`,
            );
          }

          if (r.status === 2) {
            throw new Error(
              `[safety-guard] apply_patch blockiert — Ziel-Pfad "${pfad}" ` +
                `ist nicht erlaubt.\n${r.stderr || "Vom Safety-Guard blockiert."}`,
            );
          }
        }

        // Alle Ziel-Pfade erlaubt -> Patch darf laufen.
        return;
      }

      // --- Regulaerer Fall: Tools mit genau einem Argument ---
      const mapping = TOOL_MAP[toolName];
      if (!mapping) {
        // Unbekanntes/nicht-gegatetes Tool -> bewusst durchlassen (s.o.).
        return;
      }

      const payload = args[mapping.argKey];
      if (typeof payload !== "string" || payload === "") {
        // Kein verwertbares Argument -> nichts zu pruefen, durchlassen.
        return;
      }

      const r = rufeGuard(
        guardPath,
        mapping.toolName,
        mapping.inputKey,
        payload,
        inp.sessionID,
      );

      // spawnSync-Fehler (z.B. python3 fehlt): NICHT stillschweigend durchlassen
      // bei einem real existierenden Guard — das waere ein Schutz-Loch. Wir
      // blocken hier defensiv, damit ein kaputtes Setup auffaellt statt den
      // Schutz lautlos abzuschalten.
      if (r.error) {
        throw new Error(
          `[safety-guard] Konnte command-guard.py nicht ausführen: ` +
            `${r.error.message}. Tool-Call vorsorglich blockiert. ` +
            `(python3 im PATH? Guard-Pfad korrekt?)`,
        );
      }

      if (r.status === 2) {
        // Block: stderr des Guards als Begruendung weiterreichen.
        throw new Error(r.stderr || "Tool-Call vom Safety-Guard blockiert.");
      }

      // Exit 0 (oder alles ausser 2) -> erlauben. Der Guard selbst entscheidet
      // deterministisch; ein unerwarteter Nicht-2-Code wird wie "erlaubt"
      // behandelt, weil der Guard bei echten Blocks immer exakt 2 liefert.
      return;
    },
  };
};
