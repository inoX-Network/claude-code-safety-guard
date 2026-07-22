// Verifiziert das aktualisierte Plugin (nach API-Abgleich gegen 1.17.7):
// - benannter Export vorhanden, KEIN Default-Export
// - Hook tool.execute.before ist callable
// - ein geblocktes bash-Tool wirft (throw)
// - apply_patch IST gegated: Patch auf geschuetzten Pfad wirft, harmloser nicht,
//   unlesbares Patch-Format wirft (fail-closed). Frueher war apply_patch bewusst
//   ungegated — das war die Luecke, die in der Sandbox versteckt lag.
// Aufruf: node opencode/test_plugin_load.mjs   (Node >= 22 mit --experimental-strip-types,
// node >= 23 automatisch). Setzt SAFETY_GUARD_PATH + CLAUDE_SECURITY_RULES auf Repo.
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import os from "node:os";
import fs from "node:fs";

const here = dirname(fileURLToPath(import.meta.url));
const repo = join(here, "..");
process.env.SAFETY_GUARD_PATH = join(repo, "hooks", "command-guard.py");
process.env.CLAUDE_SECURITY_RULES = join(repo, "security-rules.example.json");
// override/audit/dev in tempdir isolieren
const tmp = fs.mkdtempSync(join(os.tmpdir(), "sg-plugin-"));
process.env.CLAUDE_SUDO_OVERRIDES_DIR = tmp;
process.env.CLAUDE_AUDIT_DIR = tmp;
process.env.CLAUDE_HOOK_DEV_FLAG = join(tmp, "_no_dev_flag");

const mod = await import("./plugin/safety-guard.ts");

const results = [];
const ok = (name, cond) => results.push([name, !!cond]);

ok("named export SafetyGuardPlugin vorhanden", typeof mod.SafetyGuardPlugin === "function");
ok("KEIN default export", mod.default === undefined);

const hooks = await mod.SafetyGuardPlugin({});
const before = hooks["tool.execute.before"];
ok("hook tool.execute.before ist function", typeof before === "function");

// geblockt: bash mit gefaehrlichem Kommando -> muss werfen
const dangerous = ["r", "m", " -rf /"].join("");
let threwBash = false;
try { await before({ tool: "bash" }, { args: { command: dangerous } }); }
catch { threwBash = true; }
ok("bash gefaehrlich -> throw (block)", threwBash);

// erlaubt: harmloses bash -> kein throw
let threwLs = false;
try { await before({ tool: "bash" }, { args: { command: "ls -la" } }); }
catch { threwLs = true; }
ok("bash 'ls -la' -> kein throw (allow)", !threwLs);

// apply_patch auf geschuetzten Pfad -> muss werfen. Absoluter Pfad, damit der
// Fall unabhaengig vom Arbeitsverzeichnis eindeutig ist.
const boeserPatch = [
  "*** Begin Patch",
  "*** Update File: /etc/passwd",
  "*** End Patch",
].join("\n");
let threwBoeserPatch = false;
try { await before({ tool: "apply_patch" }, { args: { patchText: boeserPatch } }); }
catch { threwBoeserPatch = true; }
ok("apply_patch auf /etc/passwd -> throw (block)", threwBoeserPatch);

// apply_patch auf harmlose Projektdatei -> darf NICHT werfen (kein Fehlalarm)
const harmloserPatch = [
  "*** Begin Patch",
  "*** Update File: src/foo.ts",
  "*** End Patch",
].join("\n");
let threwHarmlos = false;
try { await before({ tool: "apply_patch" }, { args: { patchText: harmloserPatch } }); }
catch { threwHarmlos = true; }
ok("apply_patch auf src/foo.ts -> kein throw (allow)", !threwHarmlos);

// Unlesbares Patch-Format -> fail-closed, muss werfen. Was der Guard nicht
// parsen kann, kann er nicht pruefen -> durchlassen waere die Luecke.
let threwKaputt = false;
try { await before({ tool: "apply_patch" }, { args: { patchText: "voellig kaputtes Format" } }); }
catch { threwKaputt = true; }
ok("apply_patch mit unlesbarem Format -> throw (fail-closed)", threwKaputt);

fs.rmSync(tmp, { recursive: true, force: true });

let allPass = true;
for (const [name, pass] of results) {
  if (!pass) allPass = false;
  console.log(`${pass ? "PASS" : "FAIL"}  ${name}`);
}
console.log(`\nPlugin-Load: ${results.filter(r => r[1]).length}/${results.length} passed`);
process.exit(allPass ? 0 : 1);
