#!/usr/bin/env node
/**
 * test_v2_adapter.mjs -- the opencode 2 adapter against a copy of the guard.
 *
 * Checks the REAL function from v2/server.js (import, no rebuilt call path).
 * With "--v1" the same cases run against the old adapter
 * (plugin/safety-guard.ts) -- with the tool names and arguments opencode 2.0.8
 * really sends. That is the before picture: every case that must block and
 * passes there was open under opencode 2.
 *
 * Isolation: guard and rules come from this repository, the guard as a copy in
 * a fresh tempdir. Overrides, audit log and dev flag point into the tempdir --
 * nothing is written to a real log, nothing is measured against a live guard.
 * CLAUDE_GUARD_CONFIG points at an empty file, so the guard answers in English.
 *
 * Setup:  (cd opencode/v2 && npm ci --ignore-scripts --omit=optional)
 * Run:    node opencode/test_v2_adapter.mjs [--v1]
 */

import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
// The same file server.js resolves for "effect" -- a second instance would
// falsify the wiring check below.
import { Effect, Exit } from "./v2/node_modules/effect/dist/index.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, "..");
const V1 = process.argv.includes("--v1");
// ADAPTER_FILE: for mutation runs, a copy next to server.js (same packages)
const {
  default: plugin,
  decide,
  mcpMap,
} = await import(pathToFileURL(join(HERE, "v2", process.env.ADAPTER_FILE || "server.js")).href);

const tmp = mkdtempSync(join(tmpdir(), "safety-guard-v2-"));
const guardSource = readFileSync(join(REPO, "hooks", "command-guard.py"), "utf-8");

function guardFile(name, content) {
  const p = join(tmp, name);
  writeFileSync(p, content);
  chmodSync(p, 0o755);
  return p;
}
const intact = guardFile("intact.py", guardSource);
const syntaxError = guardFile("syntax-error.py", "def (\n" + guardSource);
const empty = guardFile("empty.py", "");
const exit3 = guardFile("exit3.py", "import sys\nsys.exit(3)\n");
// Hyphenated: not a valid module name, so it shadows no standard module.
const killed = guardFile("dies-by-signal.py", "import os, signal\nos.kill(os.getpid(), signal.SIGKILL)\n");
const notInstalled = join(tmp, "does-not-exist.py");

writeFileSync(join(tmp, "empty-config.json"), "{}");
process.env.CLAUDE_SECURITY_RULES = join(REPO, "security-rules.example.json");
process.env.CLAUDE_SUDO_OVERRIDES_DIR = join(tmp, "overrides");
process.env.CLAUDE_AUDIT_DIR = join(tmp, "audit");
process.env.CLAUDE_HOOK_DEV_FLAG = join(tmp, "no-dev-mode.json");
process.env.CLAUDE_GUARD_CONFIG = join(tmp, "empty-config.json");
mkdirSync(join(tmp, "overrides"));

// Targets assembled from parts, so this file does not itself look like an access.
const HOME = homedir();
const selfProtected = join(HOME, "." + "claude", "settings" + ".json");
const keys = join(HOME, "." + "ssh");
const project = join(HOME, "project-does-not-exist");
const harmless = join(tmp, "harmless.txt");
const envName = "prod." + "env";

// MCP map as built from the tool list (measured: id "<ns>_<name>").
const mcp = mcpMap([
  { id: "probe_probe_tool", options: { namespace: "probe" } },
  { id: "probe_get_status", options: { namespace: "probe" } },
  // The server name decides: context7 is "safe", postgres "gate" (example rules)
  { id: "context7_resolve_library", options: { namespace: "context7" } },
  { id: "postgres_list_tables", options: { namespace: "postgres" } },
  { id: "opencode_session_move", options: { namespace: "opencode" } },
  { id: "browser_tabs_list", options: { namespace: "browser.tabs" } },
]);

// ---------------------------------------------------------------------------
// Two checkers: v2 (server.js) and v1 (the old adapter)
// ---------------------------------------------------------------------------

async function checkV2(guard, tool, input, directory) {
  process.env.SAFETY_GUARD_PATH = guard;
  const reason = decide(tool, input, directory, mcp, "ses_test");
  return { blocks: reason !== null, reason: reason ?? "" };
}

let oldPlugin;
async function checkV1(guard, tool, input, directory) {
  oldPlugin ??= (await import(join(HERE, "plugin", "safety-guard.ts"))).SafetyGuardPlugin;
  process.env.SAFETY_GUARD_PATH = guard;
  try {
    const hooks = await oldPlugin({ directory });
    await hooks["tool.execute.before"]({ tool, sessionID: "ses_test" }, { args: input });
    return { blocks: false, reason: "" };
  } catch (e) {
    return { blocks: true, reason: String(e?.message ?? e) };
  }
}

const check = V1 ? checkV1 : checkV2;

// ---------------------------------------------------------------------------
// Cases: (name, guard, tool, input, directory, must block)
// Tool names and arguments as opencode 2.0.8 sends them.
// ---------------------------------------------------------------------------

const patch = (target) => ({ patchText: `*** Begin Patch\n*** Update File: ${target}\n@@\n-a\n+b\n*** End Patch` });

const CASES = [
  // Harmless list: runs without the guard (free even with a broken guard).
  ["skill is harmless", syntaxError, "skill", { id: "x" }, tmp, false],
  ["question is harmless", syntaxError, "question", { questions: [] }, tmp, false],
  ["subagent is harmless", syntaxError, "subagent", { agent: "general", description: "d", prompt: "p" }, tmp, false],

  // Refused and unknown: blocks without the guard.
  ["execute is refused", intact, "execute", { code: "1" }, tmp, true],
  ["unknown tool blocks", intact, "does_not_exist", {}, tmp, true],
  ["built-in namespace blocks", intact, "opencode_session_move", { directory: "/" }, tmp, true],
  ["browser namespace blocks", intact, "browser_tabs_list", {}, tmp, true],

  // shell -> Bash
  ["shell harmless", intact, "shell", { command: "echo hello" }, tmp, false],
  ["shell writes self-protected file", intact, "shell", { command: `echo x > ${selfProtected}` }, tmp, true],
  // "./": a bare "settings.json" is deliberately not resolved by the guard
  // (a bare word is usually a subcommand) -- a guard limit, not the adapter's.
  // What is checked here is that workdir arrives as cwd.
  ["shell relative, workdir points there", intact, "shell", { command: "echo x > ./settings.json", workdir: join(HOME, "." + "claude") }, tmp, true],
  ["shell without command blocks", intact, "shell", {}, tmp, true],

  // read/write/edit -> Read/Write/Edit with an absolute path
  ["read harmless", intact, "read", { path: harmless }, tmp, false],
  ["read key directory", intact, "read", { path: join(keys, "id_ed25519") }, tmp, true],
  ["read bare env name, relative", intact, "read", { path: envName }, project, true],
  ["write self-protected", intact, "write", { path: selfProtected, content: "x" }, tmp, true],
  ["write via ../ from the project", intact, "write", { path: "../." + "claude/settings.json", content: "x" }, project, true],
  ["write harmless", intact, "write", { path: harmless, content: "x" }, tmp, false],
  ["edit self-protected", intact, "edit", { path: selfProtected, oldString: "a", newString: "b" }, tmp, true],

  // patch -> one Write per target
  ["patch on self-protected", intact, "patch", patch(selfProtected), tmp, true],
  ["patch harmless", intact, "patch", patch(harmless), tmp, false],
  ["patch without target blocks", intact, "patch", { patchText: "*** Begin Patch\n*** End Patch" }, tmp, true],
  ["patch renames onto self-protected", intact, "patch", {
    patchText: `*** Begin Patch\n*** Update File: ${harmless}\n*** Move to: ${selfProtected}\n@@\n-a\n+b\n*** End Patch`,
  }, tmp, true],

  // grep -> Grep (recursive read of the search path)
  ["grep in key directory", intact, "grep", { pattern: "PRIVATE", path: keys }, tmp, true],
  ["grep without path, session in key dir", intact, "grep", { pattern: "PRIVATE" }, keys, true],
  ["grep harmless", intact, "grep", { pattern: "x", path: tmp }, tmp, false],

  // glob, webfetch, websearch -> mapped, free in the normal case
  ["glob harmless", intact, "glob", { pattern: "*.txt" }, tmp, false],
  ["webfetch mapped", intact, "webfetch", { url: "https://example.org" }, tmp, false],
  ["websearch mapped", intact, "websearch", { query: "opencode" }, tmp, false],

  // MCP -> mcp__<server>__<name>, the guard's policy decides
  ["MCP writing/unknown blocks", intact, "probe_probe_tool", { text: "x" }, tmp, true],
  ["MCP reading passes", intact, "probe_get_status", {}, tmp, false],
  ["MCP safe server passes, even writing", intact, "context7_resolve_library", {}, tmp, false],
  ["MCP gate server blocks, even reading", intact, "postgres_list_tables", {}, tmp, true],

  // Contract: a damaged guard blocks, a missing one passes.
  ["syntax error (exit 1)", syntaxError, "write", { path: harmless, content: "x" }, tmp, true],
  ["empty file (exit 0)", empty, "write", { path: harmless, content: "x" }, tmp, true],
  ["foreign code (exit 3)", exit3, "write", { path: harmless, content: "x" }, tmp, true],
  ["killed by a signal", killed, "shell", { command: "echo hello" }, tmp, true],
  ["patch + syntax error", syntaxError, "patch", patch(harmless), tmp, true],
  ["guard not installed at all", notInstalled, "write", { path: harmless, content: "x" }, tmp, false],
];

let failed = 0;
console.log(`opencode 2 adapter against a guard copy (${V1 ? "OLD v1 adapter" : "v2/server.js"})\n`);
for (const [name, guard, tool, input, directory, mustBlock] of CASES) {
  const { blocks, reason } = await check(guard, tool, input, directory);
  const ok = blocks === mustBlock;
  if (!ok) failed++;
  console.log(`  ${ok ? "ok  " : "FAIL"} ${name.padEnd(42)} want ${mustBlock ? "blocks" : "passes"}  got ${blocks ? "blocks" : "passes"}`);
  // On a mismatch, show the REASON: a test that counts every error as
  // "blocked" goes green when only the test's own call is broken.
  if (!ok && reason) for (const l of reason.split("\n").slice(0, 6)) console.log(`       ${l.slice(0, 160)}`);
}

// ---------------------------------------------------------------------------
// Wiring: the Effect hook returns a Tool.Error, or success
// ---------------------------------------------------------------------------
if (!V1) {
  let hook;
  const ctx = {
    location: { directory: tmp },
    tool: {
      transform: (cb) => Effect.sync(() => cb({ list: () => [] })),
      hook: (name, cb) => Effect.sync(() => { if (name === "execute.before") hook = cb; }),
    },
  };
  Effect.runSync(plugin.effect(ctx));
  process.env.SAFETY_GUARD_PATH = intact;
  const blocked = Effect.runSyncExit(hook({ tool: "execute", input: { code: "1" }, sessionID: "s" }));
  const passed = Effect.runSyncExit(hook({ tool: "skill", input: { id: "x" }, sessionID: "s" }));
  // An input whose reading throws: an error INSIDE the adapter must not pass.
  const throwing = { get command() { throw new Error("broken input"); } };
  const internal = Effect.runSyncExit(hook({ tool: "shell", input: throwing, sessionID: "s" }));
  const error = (exit) => exit.cause?.reasons?.[0]?.error;
  const tag = Exit.isFailure(blocked) ? error(blocked)?._tag ?? JSON.stringify(blocked.cause).slice(0, 120) : "no error";
  const wiring = [
    ["hook refuses with a Tool.Error", Exit.isFailure(blocked) && String(tag).includes("Tool.Error")],
    // execute also blocks as unknown -- only the reason proves its own refusal
    ["execute refusal names Code Mode", Exit.isFailure(blocked) && String(error(blocked)?.message).includes("Code Mode")],
    ["hook lets harmless calls through", Exit.isSuccess(passed)],
    ["internal adapter error blocks", Exit.isFailure(internal) && String(error(internal)?.message).includes("Internal error")],
  ];
  for (const [name, ok] of wiring) {
    if (!ok) failed++;
    console.log(`  ${ok ? "ok  " : "FAIL"} ${name}${ok ? "" : `  (${tag})`}`);
  }
  CASES.push(...wiring);
}

rmSync(tmp, { recursive: true, force: true });
console.log(`\n${CASES.length - failed}/${CASES.length} passed`);
process.exit(failed ? 1 : 0);
