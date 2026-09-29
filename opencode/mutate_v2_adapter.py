#!/usr/bin/env python3
"""Mutation runs for opencode/v2/server.js.

One change per rule, in a copy (v2/mutant.js, same packages), then
test_v2_adapter.mjs against it. A mutation must turn the test red ("killed").
If one survives, no case carries that rule on its own.

The original file is never touched. Every search string must occur exactly
once, otherwise the script stops -- a mutation that changes nothing would be
miscounted as "survived".

Run: python3 opencode/mutate_v2_adapter.py
"""
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SOURCE = HERE / "v2" / "server.js"
MUTANT = HERE / "v2" / "mutant.js"

MUTATIONS = [
    ("harmless list without subagent",
     '"skill", "question", "subagent"]', '"skill", "question"]'),
    ("harmless list without question",
     '"skill", "question", "subagent"]', '"skill", "subagent"]'),
    ("execute no longer refused",
     '  [\n    "execute",', '  [\n    "execute-never",'),
    ("built-in namespaces taken as MCP",
     "return BUILT_IN_NAMESPACES.some(", "return false && BUILT_IN_NAMESPACES.some("),
    ("MCP map empty",
     "map.set(t.id, `mcp__${ns}__${name}`);", ""),
    ("MCP name without its server",
     "`mcp__${ns}__${name}`", "`mcp__x__${name}`"),
    ("rename target in a patch ignored",
     "[PATCH_TARGET_REGEX, PATCH_MOVE_REGEX]", "[PATCH_TARGET_REGEX]"),
    ("relative path not made absolute",
     ": resolve(directory, path);", ": path;"),
    ("workdir ignored",
     "const cwd = text(a.workdir) ? absolute(a.workdir, directory) : directory;",
     "const cwd = directory;"),
    ("shell without command runs",
     'if (!command) return missing("command");', 'if (!command) return { harmless: true };'),
    ("patch without target runs",
     "if (targets.length === 0) {", "if (false) {"),
    ("webfetch not mapped",
     'case "webfetch": {', 'case "webfetch-never": {'),
    ("websearch not mapped",
     'case "websearch": {', 'case "websearch-never": {'),
    ("glob not mapped",
     'case "glob": {', 'case "glob-never": {'),
    ("grep not mapped",
     'case "grep": {', 'case "grep-never": {'),
    ("unknown tool passes",
     "  return {\n    reason:\n      `Unknown tool", "  return { harmless: true, x:\n      `Unknown tool"),
    ("only exit 2 blocks",
     "if (r.status !== 0) {", "if (r.status === 2) {"),
    ("empty guard allowed",
     "if (statSync(path).size === 0) {", "if (false) {"),
    ("missing guard blocks",
     "    return null;\n  }\n  if (statSync", '    return "blocks";\n  }\n  if (statSync'),
    ("refusal without Tool.Error",
     "Effect.fail(new Tool.Error({ message: reason }))", "Effect.void"),
    ("internal error passes",
     "reason = `[safety-guard] Internal error", "reason = null; void `[safety-guard] Internal error"),
]


def main() -> int:
    source = SOURCE.read_text(encoding="utf-8")
    env = {**os.environ, "ADAPTER_FILE": MUTANT.name}
    survived = []
    try:
        for name, old, new in MUTATIONS:
            count = source.count(old)
            if count != 1:
                print(f"STOP: '{name}' -- search string found {count}x, expected 1x")
                return 2
            MUTANT.write_text(source.replace(old, new), encoding="utf-8")
            run = subprocess.run(["node", str(HERE / "test_v2_adapter.mjs")], env=env,
                                 capture_output=True, text=True, timeout=300)
            last = (run.stdout.strip().splitlines() or ["?"])[-1]
            killed = run.returncode != 0
            if not killed:
                survived.append(name)
            print(f"  {'killed  ' if killed else 'SURVIVED'}  {name:36} {last}")
    finally:
        MUTANT.unlink(missing_ok=True)
    print(f"\n{len(MUTATIONS) - len(survived)}/{len(MUTATIONS)} mutations killed")
    return 1 if survived else 0


if __name__ == "__main__":
    sys.exit(main())
