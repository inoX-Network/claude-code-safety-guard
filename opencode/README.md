# Safety-Guard für opencode

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
  `write`/`edit`/`patch` → `Write`/`Edit/file_path`.
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

## What to verify against your opencode version

Diese Punkte sind aus den opencode-Docs hergeleitet, **nicht** gegen den
`@opencode-ai/plugin`-TypeScript-Typ der jeweils installierten Version verifiziert.
Bitte prüfen:

1. **Hook-Signatur.** Das Plugin nutzt das Event `tool.execute.before` mit der
   Signatur `async (input, output) => {}`, wobei `input.tool` der Tool-Name
   (`"bash"`, `"read"`, ...) und `output.args` die strukturierten Argumente sind
   (`output.args.command` für bash, `output.args.filePath` für Datei-Tools).
   Stimmen diese Feldnamen mit deiner Version überein? Bei Abweichung das Mapping
   in `safety-guard.ts` (`TOOL_MAP`, `argKey`) anpassen.

2. **Blocken via `throw`.** Das Plugin blockt durch `throw new Error(...)` im
   Hook. Prüfe, dass deine opencode-Version einen geworfenen Fehler in
   `tool.execute.before` tatsächlich als Abbruch des Tool-Calls behandelt.

3. **`input.sessionID` / `input.callID`.** Diese Felder sind in den Docs nicht
   eindeutig zugesichert. Das Plugin behandelt sie defensiv (optional) und
   verlässt sich nicht darauf; `session_id` wird nur weitergegeben, wenn
   vorhanden.

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
