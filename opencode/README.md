# Safety guard for opencode

**Which adapter you need depends on your opencode version** (`opencode --version`):

| opencode | adapter | status |
|---|---|---|
| **2.x** | `opencode/v2/` (plugin directory, this section) | measured against 2.0.8 |
| 1.x | `opencode/plugin/safety-guard.ts` (German section below) | measured against 1.17.7 |

**opencode 2 does not load the 1.x plugin.** It expects a plugin *directory*
in a new format, and the tools changed their names (`bash` → `shell`,
`apply_patch` → `patch`) and arguments (`filePath` → `path`). If you updated
opencode and kept the old plugin, your tool calls are not checked — measured:
the old plugin stays silent, and even if it loaded, 23 of the 24 blocking
cases of `test_v2_adapter.mjs --v1` pass through it (the one it holds is the
empty guard file, caught by its size check).

## opencode 2.x

### Install

```sh
cd opencode/v2
npm ci --ignore-scripts --omit=optional   # two pinned packages, no install scripts
```

Then list the directory under `plugins` in your opencode configuration
(`~/.config/opencode/opencode.json` or the project's `opencode.json`), with
an absolute path:

```json
{ "plugins": ["/path/to/this/repo/opencode/v2"] }
```

`SAFETY_GUARD_PATH`, `CLAUDE_SECURITY_RULES` work as for 1.x (below).

**Why two packages:** `@opencode/schema` supplies `Tool.Error` — in opencode 2
a hook can refuse a call only with that error, anything else is treated as a
crash. `effect` is the runtime opencode 2 plugins are written in. Both are
pinned to the versions opencode 2.0.8 itself ships with. `@opencode/plugin`
is deliberately not used: its `define()` returns its argument unchanged, and
it pulls in a large dependency tree (cloud SDKs, npm internals) for nothing.

### What it does

| opencode 2 tool | checked as | notes |
|---|---|---|
| `shell` | `Bash` | `workdir` becomes the guard's `cwd` |
| `read`, `write`, `edit` | `Read`, `Write`, `Edit` | path made absolute first |
| `patch` | `Write`, once per target | `Add/Update/Delete File` and `Move to`; one refusal blocks the patch |
| `grep` | `Grep` | ripgrep with `--hidden` reads file contents; the guard checks it as a recursive read |
| `glob` | `Glob` | |
| `webfetch`, `websearch` | `WebFetch`, `WebSearch` | |
| MCP tools | `mcp__<server>__<tool>` | server taken from the tool list opencode hands the plugin, not guessed from the name |
| `skill`, `question`, `subagent` | not checked — harmless list | a subagent's own calls pass through the hook one by one (measured) |
| `execute` (Code Mode) | **refused** | reaches the network through `fetch` and, through its catalog, the built-in browser tools, `opencode_session_move` and MCP servers |
| anything else | **refused** | a tool nobody mapped is not let through unchecked |

**Every path reaches the guard absolute.** The guard recognises a path only
when it contains a slash or starts with `~`; a bare `prod.env` relative to the
project would be plain text to it.

**`execute` is the large one.** The tool list opencode hands a plugin holds
59 tools in 2.0.8, not the 12 the model sees directly: 44 of them control a
built-in browser (`browser_evaluate`, `browser_files_upload`, …), all reachable
only through Code Mode. MCP tools, too, are Code-Mode-only by default
(`codemode: true`). Refusing `execute` closes that whole surface at once.

The contract from `docs/tool-chains.md` holds unchanged: only exit 0 allows,
an empty guard file blocks, a missing guard warns once and passes, and an
error inside the adapter blocks.

### What was measured, and how

Nothing here is taken from documentation. opencode 2 was driven by a
stand-in model (`live/fake_model.py`, an OpenAI-format server on 127.0.0.1
playing fixed tool calls) — no real model, no cost:

- The plugin directory is loaded; `execute.before` fires before every tool
  call of the model **and before opencode's own permission prompt**.
- A subagent's calls — foreground and background — reach the hook one by one.
- The server's shell endpoint (a command the *human* types, like `!` in
  Claude Code) does not trigger the hook. Intended, not a gap.
- The old configuration form `mcp.<name>` silently drops `codemode` when
  opencode converts it; only `mcp.servers.<name>` keeps it.

**Not measured:** a direct MCP call. Even with `codemode: false`, opencode
2.0.8 did not offer the MCP tool to the model. The adapter maps it through the
tool list and blocks what it cannot attribute.

**Side effect worth knowing:** opencode CLI subcommands such as
`opencode debug config` start a background `opencode serve --service` that
keeps running. Check with `pgrep -af "opencode serve"` after you try things.

### Tests

```sh
node opencode/test_v2_adapter.mjs          # 42 cases against a guard copy
node opencode/test_v2_adapter.mjs --v1     # the same cases against the 1.x plugin
python3 opencode/mutate_v2_adapter.py      # one mutation per rule, all must be killed
sh opencode/live/live_check.sh "$(mktemp -d)"   # real opencode, stand-in model
```

The live check seals everything off: empty XDG directories, `HOME` pointing
into the throwaway directory, a guard copy, and the configuration passed in
`OPENCODE_CONFIG_CONTENT` — no config file is written. The read probe uses a
relative env file with dummy content, never real keys: the guard resolves `~`
through the real account, not through `HOME`. Run it once with
`ADAPTER_DIR=<empty directory>`: the "blocked" checks must then fail, or the
check proves nothing.

---

# Safety-Guard für opencode 1.x

Port des deterministischen `hooks/command-guard.py`-Gates für
[opencode](https://github.com/sst/opencode). Dasselbe Python-Skript, das unter
Claude Code als PreToolUse-Hook gefährliche Tool-Calls blockiert, wird hier über
ein opencode-Plugin VOR jedem Tool-Call aufgerufen.

Das Plugin ist eine dünne **Bridge**: Es mappt opencodes Tool-Aufrufe auf das
command-guard-JSON, ruft `command-guard.py` per `child_process` auf und blockt den
Tool-Call (`throw`), wenn der Guard mit Exit-Code 2 antwortet.

## Voraussetzungen

- Eine installierte `command-guard.py` (dieses Repo, `hooks/command-guard.py`).
- Eine `security-rules.json` (Vorlage: `security-rules.example.json` im Repo-Root).
- `python3` im PATH der opencode-Umgebung.

## Installation

1. **Plugin ablegen.** opencode lädt Plugins aus `.opencode/plugin/`
   (projektlokal) oder `~/.config/opencode/plugin/` (global). Kopiere bzw.
   verlinke `opencode/plugin/safety-guard.ts` dorthin:

   ```bash
   mkdir -p ~/.config/opencode/plugin
   ln -s "$(pwd)/opencode/plugin/safety-guard.ts" \
         ~/.config/opencode/plugin/safety-guard.ts
   ```

2. **Guard-Pfad setzen.** Das Plugin sucht `command-guard.py` standardmäßig unter
   `~/.claude/hooks/command-guard.py`. Liegt der Guard woanders, setze
   `SAFETY_GUARD_PATH`:

   ```bash
   export SAFETY_GUARD_PATH="/pfad/zu/diesem/repo/hooks/command-guard.py"
   ```

3. **Regeln teilen.** Der Guard liest seine Regeln aus `CLAUDE_SECURITY_RULES`
   (env) oder `~/.claude/safety-guard/security-rules.json`. Du kannst dieselbe
   `security-rules.json` für Claude Code und opencode verwenden:

   ```bash
   export CLAUDE_SECURITY_RULES="$HOME/.claude/safety-guard/security-rules.json"
   ```

   Diese ENV-Variablen müssen in der Umgebung gesetzt sein, in der opencode läuft
   (z.B. in der Shell-Rc-Datei), damit der per `python3` aufgerufene Guard sie sieht.

## Verhalten

- **Geprüfte Tools:** `bash` → `Bash/command`, `read` → `Read/file_path`,
  `write` → `Write/file_path`, `edit` → `Edit/file_path`,
  `apply_patch` → `Write/file_path` **je Ziel-Pfad im Patch** (siehe unten).
- **`apply_patch` wird geprüft** (seit dem Schließen der Lücke). opencodes
  Multi-File-Patch-Tool liefert `patchText` (einen Diff über ggf. mehrere Dateien)
  statt eines einzelnen `filePath`. Das Plugin zerlegt den Patch in seine
  Ziel-Pfade (`*** Add/Update/Delete File:` und `*** Move to:`) und schickt **jeden
  einzeln** als `Write` durch den Guard. Ein blockierter Ziel-Pfad blockt den
  **ganzen** Patch — ein Patch ist atomar, halb anwenden gibt es nicht.
  - **Absolute Auflösung ist der Sicherheitskern:** Patch-Pfade sind *relativ* zum
    Arbeitsverzeichnis. Unaufgelöst könnte der Guard `../../.claude/settings.json`
    nicht gegen seine Self-Protect-Liste matchen und würde durchwinken. Das Plugin
    löst deshalb jeden Pfad gegen das Projektverzeichnis absolut auf, **bevor** der
    Guard ihn sieht.
  - **Fail-closed bei unlesbarem Patch:** Liegt ein `patchText` vor, in dem kein
    einziger Ziel-Pfad erkennbar ist, blockiert das Plugin. Was sich nicht parsen
    lässt, lässt sich nicht prüfen.
  - Warum das zählt: Solange opencode in einer Sandbox lief, fing die Sandbox diesen
    Weg mit auf. Läuft opencode **ungesandboxt** auf dem Host (Guard als Autorität,
    wie unter Claude Code), war `apply_patch` zuvor ein Schreibkanal ganz ohne Bremse.
    Ein Verlass auf `permission.edit` allein reicht nicht — steht es auf `"allow"`,
    ist der Weg offen.
- **Nicht geprüfte Tools** (z.B. `list`, `glob`, `grep`, `webfetch`, MCP-Tools)
  werden **bewusst durchgelassen** — der Guard hat dafür keine Regeln, und ein
  pauschales Blocken würde jede Session unbrauchbar machen.
- **Block:** Bei Exit 2 wirft das Plugin einen Fehler mit der stderr-Begründung
  des Guards → opencode bricht den Tool-Call ab.
- **Fail-open NUR bei fehlendem Guard:** Ist `command-guard.py` nicht auffindbar,
  warnt das Plugin **einmalig** auf stderr und lässt durch (sonst wäre opencode
  ohne Guard unbenutzbar). Das ist die einzige bewusste fail-open-Stelle — der
  Guard selbst ist fail-closed.
- **Fail-closed bei kaputtem Setup:** Existiert der Guard, lässt sich aber nicht
  ausführen (z.B. `python3` fehlt), **blockiert** das Plugin vorsorglich, damit
  der Schutz nicht lautlos abgeschaltet wird.

## Testen ohne opencode

Die sicherheitskritische Bridge-Logik lässt sich isoliert prüfen:

```bash
node opencode/test_bridge.mjs
```

Der Test baut das command-guard-JSON wie das Plugin, ruft `command-guard.py` mit
isolierten override-/audit-Verzeichnissen (tempdir) und der Repo-Beispielregeln
auf und erwartet:

| Tool | Eingabe | erwartet |
|------|---------|----------|
| bash | `rm -rf /` | Block (2) |
| bash | `cat ~/.ssh/id_rsa` | Block (2) |
| read | `~/.ssh/id_rsa` | Block (2) |
| bash | `python3 -c open("~/.ssh/id_rsa")` | Block (2) |
| bash | `ls -la` | Allow (0) |
| read | `data.json` | Allow (0) |

Für `apply_patch` gibt es eine eigene Suite, die die **echte** Parser-Funktion aus
`safety-guard.ts` importiert (kein Nachbau — Nachbauten driften) und die
aufgelösten Pfade zusätzlich End-to-End durch den Guard schickt:

```bash
node opencode/test_apply_patch.mjs
node opencode/test_plugin_load.mjs
```

| Patch-Inhalt | erwartet |
|--------------|----------|
| `*** Update File: ../../.claude/settings.json` | Block (Traversal → Self-Protect) |
| `*** Add File: ../../.claude/hooks/boese.py` | Block (Guard selbst) |
| `*** Update File: /etc/passwd` | Block |
| `*** Add File: ../../.ssh/authorized_keys` | Block |
| harmlose + **eine** böse Datei im selben Patch | Block (Patch ist atomar) |
| `*** Update File: src/foo.ts` | Allow |
| unlesbares Patch-Format | Block (fail-closed) |

## What to verify against your opencode version

Die Hook-Signatur, Feldnamen und Tool-IDs wurden gegen den echten Typ
`@opencode-ai/plugin@1.17.7` (`dist/index.d.ts`) und den opencode-Quellcode
verifiziert. `output.args` ist dort allerdings als `any` typisiert — die
Feldnamen sind also kein stabiler Compile-Vertrag, sondern können sich zwischen
Versionen ändern. Prüfe bei abweichender Version:

1. **Tool-ID `bash` (Stabilitäts-Risiko).** opencodes Quellcode markiert die
   Tool-ID `"bash"` ausdrücklich mit „*rename with opencode 2.0*". Ab opencode 2.0
   kann sich der Tool-Name ändern → dann greift das `bash`-Mapping nicht mehr.
   Bei einem Major-Update `TOOL_MAP` gegen die neuen Tool-IDs abgleichen.

2. **`output.args`-Felder (`any`, kein Typ-Vertrag).** Verifiziert für 1.17.7:
   `output.args.command` (bash), `output.args.filePath` (read/write/edit). Da der
   Typ `any` ist, greift das Plugin defensiv zu (Optional-Chaining) — bei
   Abweichung das Mapping in `safety-guard.ts` (`TOOL_MAP`, `argKey`) anpassen.

3. **Blocken via `throw`.** Das Plugin blockt durch `throw new Error(...)` im
   Hook (entspricht dem offiziellen opencode-Doku-Beispiel). Prüfe per E2E-Test,
   dass deine Version einen geworfenen Fehler tatsächlich als Abbruch behandelt.

4. **Subagent-Coverage.** opencode-Issue
   [#5894](https://github.com/sst/opencode/issues/5894) (Hooks feuern bei
   Subagenten/Task-Tool nicht) wurde am **2026-04-15 als gefixt geschlossen**.
   Verifiziere in deiner Version, dass `tool.execute.before` **auch für Tool-Calls
   innerhalb von Subagenten** feuert — sonst hätten Subagenten ein Schutzloch.
   (Hinweis: Das Plugin gibt mangels zuverlässiger `agent_id` keine `agent_id` an
   den Guard weiter; Subagent-Calls werden daher wie Hauptsession-Calls auf
   Override-Stufe 0 behandelt — die sichere Default-Annahme.)

## Alternative ohne Plugin

Für einfache Allow/Deny-Fälle bietet opencode eine native Bash-Denylist in
`opencode.json` (Block `permission.bash` mit Glob-Patterns → `allow`/`ask`/`deny`).
Siehe `opencode.json.example`. Diese Variante ist deutlich schwächer als der
Python-Guard: kein `.env`-/Credential-**Read**-Schutz, keine Interpreter-Fix-
Erkennung (`python3 -c open(...)`), kein Override-System. Für vollen Schutz das
Plugin verwenden.
