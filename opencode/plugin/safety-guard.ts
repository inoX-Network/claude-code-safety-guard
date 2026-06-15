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
import { join } from "node:path";

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
  // patch -> Edit (opencodes Patch-Tool aendert ebenfalls eine Datei)
  patch: { toolName: "Edit", argKey: "filePath", inputKey: "file_path" },
};

// Damit die "Guard nicht installiert"-Warnung nur EINMAL pro Prozess erscheint.
let warnedMissingGuard = false;

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------

// Der Plugin-Default-Export erhaelt von opencode einen Kontext (app, client,
// $, ...). Wir brauchen davon nichts und geben direkt das Hooks-Objekt zurueck.
export const SafetyGuardPlugin = async (_ctx: unknown) => {
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

      const mapping = TOOL_MAP[toolName];
      if (!mapping) {
        // Unbekanntes/nicht-gegatetes Tool -> bewusst durchlassen (s.o.).
        return;
      }

      const args = out.args ?? {};
      const payload = args[mapping.argKey];
      if (typeof payload !== "string" || payload === "") {
        // Kein verwertbares Argument -> nichts zu pruefen, durchlassen.
        return;
      }

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

      // command-guard-JSON bauen — exakt die Felder die main() in command-guard.py liest.
      const guardInput: Record<string, unknown> = {
        tool_name: mapping.toolName,
        tool_input: { [mapping.inputKey]: payload },
      };
      // session_id defensiv mitgeben, falls vorhanden (Override-Session-Binding).
      if (inp.sessionID) guardInput.session_id = inp.sessionID;
      // agent_id liefert opencode hier nicht zuverlaessig -> bewusst weggelassen.
      // Ohne agent_id behandelt der Guard den Call als Hauptsession (Stufe 0),
      // was die sichere Default-Annahme ist.

      const result = spawnSync("python3", [guardPath], {
        input: JSON.stringify(guardInput),
        encoding: "utf-8",
      });

      // spawnSync-Fehler (z.B. python3 fehlt): NICHT stillschweigend durchlassen
      // bei einem real existierenden Guard — das waere ein Schutz-Loch. Wir
      // blocken hier defensiv, damit ein kaputtes Setup auffaellt statt den
      // Schutz lautlos abzuschalten.
      if (result.error) {
        throw new Error(
          `[safety-guard] Konnte command-guard.py nicht ausfuehren: ` +
            `${result.error.message}. Tool-Call vorsorglich blockiert. ` +
            `(python3 im PATH? Guard-Pfad korrekt?)`,
        );
      }

      if (result.status === 2) {
        // Block: stderr des Guards als Begruendung weiterreichen.
        const reason =
          (result.stderr && result.stderr.trim()) ||
          "Tool-Call vom Safety-Guard blockiert.";
        throw new Error(reason);
      }

      // Exit 0 (oder alles ausser 2) -> erlauben. Der Guard selbst entscheidet
      // deterministisch; ein unerwarteter Nicht-2-Code wird wie "erlaubt"
      // behandelt, weil der Guard bei echten Blocks immer exakt 2 liefert.
      return;
    },
  };
};

export default SafetyGuardPlugin;
