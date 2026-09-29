/**
 * server.js -- safety-guard adapter for opencode 2.x (plugin format v2).
 *
 * The same guard (command-guard.py) that checks every tool call under Claude
 * Code checks every tool call the model makes in opencode. Measured against
 * opencode 2.0.8 with a stand-in model (opencode/live/):
 *
 *   - opencode loads this directory when it is listed under "plugins" in the
 *     configuration, and takes the default export {id, effect}.
 *   - execute.before fires BEFORE every tool call of the model, and for every
 *     inner call of a subagent (foreground and background) on its own.
 *   - It fires before opencode's own permission prompt.
 *   - The only way to refuse is a Tool.Error: the tool does not run, and the
 *     model sees the reason.
 *   - The server's shell endpoint (a command typed by the HUMAN, like "!" in
 *     Claude Code) does not trigger the hook. That is intended, not a gap.
 *
 * The integration contract (docs/tool-chains.md):
 *   1. Only exit 0 allows. Everything else blocks -- 1, 3 and death by signal
 *      too, because that is how a damaged guard ends.
 *   2. An EMPTY guard file blocks (Python exits it with 0).
 *   3. If no guard is installed at all, the adapter warns once and passes --
 *      the one deliberate fail-open.
 *   4. A HARMLESS list, not a danger list: a tool not shown to be harmless is
 *      mapped onto the guard or blocked, never skipped.
 */

import { spawnSync } from "node:child_process";
import { existsSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { isAbsolute, join, resolve } from "node:path";
import { Effect } from "effect";
import { Tool } from "@opencode/schema/tool";

// ---------------------------------------------------------------------------
// How each tool is treated
// ---------------------------------------------------------------------------

// Shown to be harmless -- run without a check:
//   skill     loads instruction text, touches nothing.
//   question  asks the human.
//   subagent  starts a subagent; every one of ITS calls passes through this
//             hook on its own (measured, foreground and background).
export const HARMLESS = new Set(["skill", "question", "subagent"]);

// Refused outright, with a reason for the model.
export const REFUSED = new Map([
  [
    "execute",
    "Code Mode (execute) is refused: it reaches the network through fetch and, " +
      "through its catalog, tools this adapter cannot check one by one " +
      "(browser control, moving the session directory, MCP servers).",
  ],
]);

// Namespaces of built-in tools. They are reachable only through Code Mode; if
// a call arrives directly anyway, it is unknown and blocked instead of being
// passed on as an MCP tool.
const BUILT_IN_NAMESPACES = ["opencode", "browser"];

function builtInNamespace(ns) {
  return BUILT_IN_NAMESPACES.some((b) => ns === b || ns.startsWith(b + "."));
}

// Builds, from the tool list (ctx.tool.transform -> editor.list()), the map
// tool id -> name for the guard, for MCP tools only. opencode reports an MCP
// tool as "<namespace>_<name>" (measured: server "probe", tool "probe_tool"
// -> id "probe_probe_tool", namespace "probe"). The guard knows MCP tools as
// "mcp__<server>__<name>".
export function mcpMap(tools) {
  const map = new Map();
  for (const t of tools ?? []) {
    const ns = t?.options?.namespace;
    if (typeof ns !== "string" || ns === "" || builtInNamespace(ns)) continue;
    const prefix = ns.replace(/\./g, "_") + "_";
    const name = t.id.startsWith(prefix) ? t.id.slice(prefix.length) : t.id;
    map.set(t.id, `mcp__${ns}__${name}`);
  }
  return map;
}

// ---------------------------------------------------------------------------
// apply_patch format (tool "patch")
// ---------------------------------------------------------------------------

// The directives that name a file as a target -- the rename target included.
const PATCH_TARGET_REGEX = /^\*\*\* (?:Add|Delete|Update) File:[ \t]*(.+?)[ \t]*$/gm;
const PATCH_MOVE_REGEX = /^\*\*\* Move to:[ \t]*(.+?)[ \t]*$/gm;

// Pulls every write target out of a patch and resolves it to absolute.
// Absolute is the traversal protection: "../../.claude/settings.json" left
// relative would slip past the guard's self-protection.
export function patchTargets(patchText, directory) {
  const found = new Set();
  for (const regex of [PATCH_TARGET_REGEX, PATCH_MOVE_REGEX]) {
    regex.lastIndex = 0; // a /g regex keeps state
    let match;
    while ((match = regex.exec(patchText)) !== null) {
      const raw = match[1]?.trim();
      if (raw) found.add(absolute(raw, directory));
    }
  }
  return [...found];
}

// Every path reaches the guard absolute: it recognises a path only when it
// contains a slash or starts with ~ -- a bare "prod.env" would be text to it.
function absolute(path, directory) {
  if (path.startsWith("~/") || path === "~") return join(homedir(), path.slice(1));
  return isAbsolute(path) ? resolve(path) : resolve(directory, path);
}

function text(value) {
  return typeof value === "string" && value !== "" ? value : null;
}

// ---------------------------------------------------------------------------
// Mapping an opencode call onto guard calls
// ---------------------------------------------------------------------------

/**
 * Translates an opencode call into what the guard has to check.
 *
 * Returns:
 *   { harmless: true }                    -- pass without a check
 *   { reason: "..." }                     -- block, without the guard
 *   { check: [{tool_name, tool_input, cwd}, ...] }  -- EACH must return 0
 */
export function mapCall(tool, input, directory, mcp = new Map()) {
  if (HARMLESS.has(tool)) return { harmless: true };
  if (REFUSED.has(tool)) return { reason: REFUSED.get(tool) };

  const a = input && typeof input === "object" ? input : {};
  const single = (tool_name, tool_input, cwd = directory) => ({
    check: [{ tool_name, tool_input, cwd }],
  });
  const missing = (field) => ({
    reason: `Tool "${tool}" has no checkable argument "${field}" — blocked as a precaution.`,
  });

  switch (tool) {
    case "shell": {
      const command = text(a.command);
      if (!command) return missing("command");
      const cwd = text(a.workdir) ? absolute(a.workdir, directory) : directory;
      return single("Bash", { command }, cwd);
    }
    case "read":
    case "write":
    case "edit": {
      const path = text(a.path);
      if (!path) return missing("path");
      const name = { read: "Read", write: "Write", edit: "Edit" }[tool];
      return single(name, { file_path: absolute(path, directory) });
    }
    case "patch": {
      const patchText = text(a.patchText);
      if (!patchText) return missing("patchText");
      const targets = patchTargets(patchText, directory);
      // A patch with no recognisable target cannot be checked -- and what
      // cannot be checked does not run.
      if (targets.length === 0) {
        return {
          reason:
            "patch: no target path found in the patch (expected '*** Add/Update/" +
            "Delete File:' or '*** Move to:') — blocked as a precaution.",
        };
      }
      return {
        check: targets.map((p) => ({
          tool_name: "Write",
          tool_input: { file_path: p },
          cwd: directory,
        })),
      };
    }
    case "grep": {
      // Reads file contents (ripgrep with --hidden). The guard checks Grep
      // like a recursive read of the search path.
      const pattern = text(a.pattern);
      if (!pattern) return missing("pattern");
      const payload = { pattern, path: absolute(text(a.path) ?? ".", directory) };
      if (text(a.include)) payload.glob = a.include;
      return single("Grep", payload);
    }
    case "glob": {
      const pattern = text(a.pattern);
      if (!pattern) return missing("pattern");
      const base = absolute(text(a.path) ?? ".", directory);
      return single("Glob", { pattern: absolute(pattern, base), path: base });
    }
    case "webfetch": {
      const url = text(a.url);
      if (!url) return missing("url");
      return single("WebFetch", { url });
    }
    case "websearch": {
      const query = text(a.query);
      if (!query) return missing("query");
      return single("WebSearch", { query });
    }
  }

  if (mcp.has(tool)) return single(mcp.get(tool), a);

  return {
    reason:
      `Unknown tool "${tool}" — the safety guard does not know it and ` +
      `therefore does not let it run unchecked.`,
  };
}

// ---------------------------------------------------------------------------
// Asking the guard
// ---------------------------------------------------------------------------

function guardPath() {
  const fromEnv = process.env.SAFETY_GUARD_PATH;
  if (fromEnv && fromEnv.trim() !== "") return fromEnv;
  return join(homedir(), ".claude", "hooks", "command-guard.py");
}

let warnedMissing = false;

/**
 * Decides on one call. Returns null = allowed, otherwise the reason for the
 * refusal.
 */
export function decide(tool, input, directory, mcp = new Map(), sessionID) {
  const plan = mapCall(tool, input, directory, mcp);
  if (plan.harmless) return null;
  if (plan.reason) return `[safety-guard] ${plan.reason}`;

  const path = guardPath();
  if (!existsSync(path)) {
    // The one deliberate fail-open (contract, duty 3).
    if (!warnedMissing) {
      warnedMissing = true;
      process.stderr.write(
        `[safety-guard] WARNING: command-guard.py not found at "${path}". ` +
          `Tool calls are NOT checked. Set SAFETY_GUARD_PATH.\n`,
      );
    }
    return null;
  }
  if (statSync(path).size === 0) {
    return (
      `[safety-guard] command-guard.py at "${path}" is EMPTY. ` +
      `Call blocked as a precaution — an empty guard allows everything.`
    );
  }

  for (const call of plan.check) {
    const payload = { ...call };
    if (sessionID) payload.session_id = sessionID;
    // opencode supplies no agent_id -- without one the call counts as the
    // main session. A subagent therefore inherits no override.
    const r = spawnSync("python3", [path], {
      input: JSON.stringify(payload),
      encoding: "utf-8",
    });
    if (r.error) {
      return (
        `[safety-guard] command-guard.py could not be run ` +
        `(${r.error.message}) — blocked as a precaution. Is python3 on the PATH?`
      );
    }
    // ONLY 0 allows (contract, duty 1).
    if (r.status !== 0) {
      const target = call.tool_input.file_path ? ` (${call.tool_input.file_path})` : "";
      return (
        (r.stderr || "").trim() ||
        `[safety-guard] ${call.tool_name}${target} blocked (exit ${r.status}).`
      );
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------

export default {
  id: "safety-guard",
  effect: (ctx) =>
    Effect.gen(function* () {
      const directory = ctx?.location?.directory || process.cwd();

      // The MCP map follows every change to the tool list (servers come and
      // go). Read only, nothing is changed.
      let mcp = new Map();
      yield* ctx.tool.transform((editor) => {
        mcp = mcpMap(editor.list());
      });

      yield* ctx.tool.hook("execute.before", (event) =>
        Effect.suspend(() => {
          let reason;
          try {
            reason = decide(event.tool, event.input, directory, mcp, event.sessionID);
          } catch (e) {
            // An error inside the adapter must not switch the protection off.
            reason = `[safety-guard] Internal error in the adapter (${e?.message ?? e}) — blocked as a precaution.`;
          }
          return reason === null ? Effect.void : Effect.fail(new Tool.Error({ message: reason }));
        }),
      );
    }),
};
