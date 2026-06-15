#!/usr/bin/env node
/**
 * test_bridge.mjs — verifiziert die BRIDGE-LOGIK des opencode-Plugins OHNE
 * opencode zu brauchen. Es baut exakt das command-guard-JSON, das
 * safety-guard.ts bauen wuerde, ruft hooks/command-guard.py damit auf stdin
 * auf und prueft den Exit-Code.
 *
 * Isolation (damit der Test nichts am echten System anfasst):
 *   - CLAUDE_SECURITY_RULES  -> security-rules.example.json des Repos
 *   - CLAUDE_SUDO_OVERRIDES_DIR / CLAUDE_AUDIT_DIR -> frisches tempdir
 *   - CLAUDE_HOOK_DEV_FLAG    -> nicht existierender Pfad (Dev-Modus aus)
 *
 * Aufruf:  node opencode/test_bridge.mjs
 */

import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, "..");
const guardPath = join(repoRoot, "hooks", "command-guard.py");
const rulesPath = join(repoRoot, "security-rules.example.json");

const tmp = mkdtempSync(join(tmpdir(), "safety-guard-bridge-"));
const env = {
  ...process.env,
  CLAUDE_SECURITY_RULES: rulesPath,
  CLAUDE_SUDO_OVERRIDES_DIR: join(tmp, "overrides"),
  CLAUDE_AUDIT_DIR: join(tmp, "audit"),
  CLAUDE_HOOK_DEV_FLAG: join(tmp, "does-not-exist.json"),
};

// Dieselbe Mapping-Logik wie safety-guard.ts (bewusst dupliziert, damit der
// Test eigenstaendig ist und nicht die TS-Datei importieren muss).
const TOOL_MAP = {
  bash: { toolName: "Bash", argKey: "command", inputKey: "command" },
  read: { toolName: "Read", argKey: "filePath", inputKey: "file_path" },
  write: { toolName: "Write", argKey: "filePath", inputKey: "file_path" },
  edit: { toolName: "Edit", argKey: "filePath", inputKey: "file_path" },
  patch: { toolName: "Edit", argKey: "filePath", inputKey: "file_path" },
};

function callGuard(opencodeTool, payload) {
  const m = TOOL_MAP[opencodeTool];
  const guardInput = {
    tool_name: m.toolName,
    tool_input: { [m.inputKey]: payload },
  };
  const res = spawnSync("python3", [guardPath], {
    input: JSON.stringify(guardInput),
    encoding: "utf-8",
    env,
  });
  if (res.error) {
    return { status: -1, stderr: String(res.error.message) };
  }
  return { status: res.status, stderr: (res.stderr || "").trim() };
}

const cases = [
  { tool: "bash", payload: "rm -rf /", expect: 2, name: "bash rm -rf /" },
  { tool: "bash", payload: "cat ~/.ssh/id_rsa", expect: 2, name: "bash cat id_rsa" },
  { tool: "read", payload: "~/.ssh/id_rsa", expect: 2, name: "read id_rsa" },
  {
    tool: "bash",
    payload: 'python3 -c open("~/.ssh/id_rsa")',
    expect: 2,
    name: "bash python3 -c open(id_rsa)",
  },
  { tool: "bash", payload: "ls -la", expect: 0, name: "bash ls -la" },
  { tool: "read", payload: "data.json", expect: 0, name: "read data.json" },
];

let failures = 0;
console.log(`Guard:  ${guardPath}`);
console.log(`Rules:  ${rulesPath}`);
console.log(`Tmp:    ${tmp}`);
console.log("");
console.log("Tool   | Case                              | erwartet | tatsaechlich | OK");
console.log("-------+-----------------------------------+----------+--------------+---");
for (const c of cases) {
  const r = callGuard(c.tool, c.payload);
  const ok = r.status === c.expect;
  if (!ok) failures++;
  console.log(
    `${c.tool.padEnd(6)} | ${c.name.padEnd(33)} | ${String(c.expect).padEnd(8)} | ` +
      `${String(r.status).padEnd(12)} | ${ok ? "JA" : "NEIN"}`,
  );
  if (!ok && r.stderr) console.log(`        -> stderr: ${r.stderr}`);
}

rmSync(tmp, { recursive: true, force: true });

console.log("");
if (failures === 0) {
  console.log("Ergebnis: ALLE 6 Bridge-Tests bestanden.");
  process.exit(0);
} else {
  console.log(`Ergebnis: ${failures} von ${cases.length} Bridge-Tests FEHLGESCHLAGEN.`);
  process.exit(1);
}
