# Changelog

Versions are dates (`YYYY.MM.DD`) and match the `VERSION` file and the git tag
of the same name.

Every entry says whether it changes **what the guard blocks**. The update check
tells you a newer version exists; this file is where you find out whether that
matters to you. Entries marked **security** close a way around the guard.

---

## 2026.10.05-5

### security — level 0 wrote as root anywhere the path list did not reach

- The example rules list `cp`, `mv`, `chmod`, `chown` and `tee` in
  `allowed_sudo`, for deploys and backups. Protection then hung on
  `blocked_paths_write` alone, and level 0 wrote as root everywhere else:
  `sudo cp … /var/spool/cron/crontabs/root`, `sudo cp … /root/.bashrc`, and
  `sudo chown root` plus `sudo chmod 4755` on one's own copy of a shell — a
  setuid-root shell in three commands, without an approval.
- A sudo whose command writes (`cp`, `mv`, `install`, `tee`, `dd`, `ln`,
  `rsync`, `chmod`, `chown`, `chgrp`, `mkdir`, `touch`, `truncate`, `rm`,
  `rmdir`, `unlink`) now needs level 1 — the pattern `systemctl` and `pacman`
  already follow. The gate sits on the verb, not on a path list that would
  never be complete. Reading as root stays free. Applies to remote commands
  too.
- Setting a setuid/setgid bit as root (`chmod 4755`, `2755`, `u+s`, `g+s`,
  `install -m 4755`) needs level 2 even with a deploy approval; the sticky bit
  (`1777`) and removing a bit (`u-s`) do not count.
- One parser for every sudo check: `check_sudo` and both new gates read a line
  through the same function.
- Cost, replayed on 5,409 distinct allowed sudo commands from a real log: 16
  newly refused — 12 local, all of them probes for this very gap; 4 real
  remote writes at level 0 in three months (deploys run with an approval
  anyway).

New test `tests/test_sudo_write_verbs.py` — 5/17 before, 17/17 after; 11/11
mutations caught. Changes what the guard blocks: **yes**.

## 2026.10.05-4

### security — the audit log stored passwords in clear text

- Redaction knew one form: `echo '<pw>' | sudo`. On a real installation the
  log held a sudo password in 84 lines, in forms it missed: the password in a
  variable used later (`PW='…'; echo "$PW" | sudo -S`, 79 lines), `printf …
  | sudo -S` (3), a brace group `{ echo "…"; cat; } | sudo -S` (2), and one
  `printf … | ssh host 'cat > ~/.askpass'`. Also open: an unquoted `echo`, a
  here-string, `--stdin`, a pipe into `ssh host sudo -S`, `sshpass -p`.
- Secret names with a prefix were missed too: the old rule wanted `password`
  as a whole word, so `DB_PASSWORD=`, `POSTGRES_PASSWORD=`, `SECRET_KEY=`,
  `TOKEN_ENC_KEY=` went in unredacted — several hundred lines in the same log.
- Now: a variable whose name contains `pw`, `pass`, `secret` or `token` is
  always redacted; `sshpass -p` is redacted; and in a line that hands sudo a
  password on stdin (`-S`, combined like `-kS`, or `--stdin`) or feeds an
  askpass helper, every `echo`/`printf` argument, here-string and variable
  value is redacted. Quote-aware, so a password containing `;`, `|` or `&`
  cannot leave its tail behind.
- Cost, measured on 105,586 distinct logged commands: 1,364 lose detail
  (1.3 %), 913 of them password lines; among the rest a few harmless names
  (`passed`, `PWD`, `bypass`).
- **A log written before this version may hold secrets.** Treat it as
  sensitive; rotate what it exposed.

New test `tests/test_audit_redacts_password_pipes.py` — 8/25 before, 25/25
after; 10/10 mutations caught. Replayed on the 84 real lines: 84 kept the
password before, 0 after. Changes what the guard blocks: **no** — it changes
what the log keeps.

## 2026.10.05-3

### A wildcard in a path list of the rules file is reported instead of failing silently

- `blocked_paths_write`, `blocked_paths_delete`, `blocked_recursive_delete`
  and the read tiers `always_blocked_reads` and `require_override_1` take
  exact paths. A wildcard there is not expanded — the entry matches nothing,
  and the path it was meant to cover is unprotected. Measured on a real
  install: `~/.claude/rate-limit.json*`, written to cover a file and its
  `.lock`/`.tmp` neighbours, left even the main file writable (9 of 20 probe
  cases protected instead of 15 with the exact path).
- The hook now names such entries to the model once per session, through the
  same channel as a missing section, and `tools/verify-install.py` warns about
  them. `always_allowed` is not checked — it understands `*`.
- Teaching every path matcher wildcards was rejected: five separate matchers
  (shell writes, inline code, downloaders, the write tool, docker mounts,
  grant reach, delete protection), the kind of change that has opened gaps
  before. If you need a family of files covered, protect the directory they
  live in.

New test `tests/test_wildcard_in_rule_paths.py` — 4/14 before, 14/14 after;
8/8 mutations caught. Changes what the guard blocks: **no** — it adds a
notice; every verdict is the same.

## 2026.10.05-2

### security — git wrote into the guard's own directories

- Self-protection checks the paths a command writes to; git writes through its
  own options. `git --work-tree <hooks dir> checkout … -- .` replaced the guard
  itself, `git -C <hooks dir> init` and `git clone <url> <hooks dir>/new` wrote
  beside it, and a release checkout under the hooks directory could be
  switched to any version — one the agent pushed itself included — with a
  single `git checkout`. 10 of 10 such calls passed.
- A git call that acts inside a self-protected path is now refused unless the
  subcommand only reads (`log`, `status`, `diff`, `show`, `describe`,
  `rev-parse`, `ls-files`, …). Where it acts comes from `-C`, `--work-tree`,
  `--git-dir`, `GIT_DIR`/`GIT_WORK_TREE`, a `cd` earlier on the line and the
  working directory the tool chain reports; for `clone`, `init`, `checkout`,
  `restore` and `worktree` also from the path arguments.
- Still open, by design: a repository that merely CONTAINS a protected
  directory (a working copy whose `shared/hooks` is the hook source) stays
  free for `switch`, `pull` and `merge`, because every session commits and
  switches branches there. A path argument pointing into the protected part is
  refused. Running the guard from a separate checkout that no session works in
  closes the rest.

New test `tests/test_git_into_self_protection.py` — 21/46 before, 46/46
after; 12/12 mutations caught at the expected case. Against a real log of
99,228 distinct allowed commands: 2 now refused, both probes of this finding.
Changes what the guard blocks: **yes**.

## 2026.10.05

### security — the agent CLI wrote its own settings and started sessions without the hooks

- The guard protects the settings file by its path. The `claude` CLI writes
  that file itself, with no path on the command line: `claude plugin disable
  <name>` rewrote it past the guard (measured live). Plugins bring their own
  hooks and MCP servers, so the same CLI could add code that runs next to the
  guard. Every subcommand that writes settings, credentials or local state —
  `plugin`/`mcp`/`marketplace` changes, `auth login`/`logout`, `import`,
  `install`, `update`, `setup-token`, `purge`, `ultrareview`, `gateway`,
  `auto-mode reset`, … — is now owner-only, with no override.
- Worse, the CLI can start a session that never loads the user's hooks, and so
  never this guard: `--safe-mode`, `--bare`, `--restricted`, `--setting-sources`
  without `user`, `--settings`, `--plugin-dir`, `--plugin-url`, `--mcp-config`,
  `--agents`, `--channels`, `--exec`, `--debug-file`, and the variables
  `CLAUDE_CODE_SAFE_MODE`, `CLAUDE_CODE_SIMPLE`, `CLAUDE_CONFIG_DIR`. Owner-only
  as well — at the command position, behind wrappers (`timeout`, `xargs`,
  `sudo -u`), in a later segment and inside `bash -c "…"`.
- An unknown subcommand right after the program name counts as writing
  (fail-closed): a future `claude <something>` must not pass because the list
  has not heard of it.
- Free on purpose: starting and managing ordinary sessions, with
  `--dangerously-skip-permissions` / `bypassPermissions` and Remote Control
  too — hooks keep running there (measured: a blocked pattern stayed blocked in
  a bypass session). `--bg`, `attach`, `respawn`, `logs`, `stop`/`kill`, `rm`,
  `daemon`, `remote-control`, `--version`, `--help`, `doctor`, `agents`, and the
  reading forms `plugin list/details/validate`, `marketplace list`,
  `mcp list/get`, `auth status`, `auto-mode config/defaults/critique`.
- A pattern a hook alone cannot close: a child session can still change a
  setting through `/config key=value` in its prompt. The real second line is a
  **managed** hook — see THREAT-MODEL.md.

New test `tests/test_agent_cli_settings.py` — 50/119 before (only the free
cases), 119/119 after; 11/11 mutations caught at the expected case. Against a
real log of 99,113 distinct allowed commands: 16 now refused — 13 are exactly
this rule's target (plugin and MCP changes, `--safe-mode`/`--settings` child
sessions), 3 are the known "a `|` inside a quoted pattern splits the line"
class.
Changes what the guard blocks: **yes**.

## 2026.10.01-9

### Messages — the last English pieces inside a translated refusal

- The "Needed: …" part of a path refusal was built in the code, so a German
  refusal read "Benötigt: level 2 OR an allowed_paths grant for '…'" — half
  English, in the sentence that tells the reader what to do. It comes from the
  catalogue now (`path.needed`).
- The write refusal said "(Write/Edit)" also for a refused Bash command. Gone,
  in English and German.
- The desktop notification for `require_confirmation` commands takes its title
  and text from the catalogue (`notify.confirm_title`, `notify.confirm_body`).

New test `tests/test_needed_text_is_catalogued.py` — 1/3 before, 3/3 after.
`tests/test_refusal_names_the_uncovered_target.py` set a `CLAUDE_GUARD_LANG`
variable the guard never read; it now runs without a configuration, so it is
English on every machine (it failed on a machine configured for German).
Changes what the guard blocks: **no**, only wording.

## 2026.10.01-8

### New, off by default — the chain approval channel

- An approval from a distance, without the `!` channel: the owner sends a
  one-time value from a chain the assistant cannot predict, and the assistant
  may run the approval script itself — in exactly ONE form, matched against
  the whole command line. A prefix, a chained command, another script path or
  other flags fall back to the hard owner-only block, as before.
- Switched on in `guard-config.json` (`chain_approval`), with the script name
  and flag names of YOUR approval script. A name or flag of an unexpected
  shape switches the channel off. The shipped `grant-override` does not take
  `--code` yet — leave it off until your script does.
- `installation.approval_scripts` (default `~/.claude/bin`) is read now, and a
  configured directory is **added to self-protection** — the channel runs a
  script from there, so the directory must not be writable for the assistant.
  Dev mode does not open it, exactly like the default `~/.claude/bin` (the
  suite caught a first version that put it on the dev-mode list).
- `.beispiel` and `.vorlage` count as template suffixes for environment files,
  next to `.example` and `.sample`.

New test `tests/test_chain_approval_switch.py` — 11/19 before, 19/19 after;
9/9 mutations killed, each on the expected case. Against the maintainer's copy,
where this channel has run since September: identical verdicts on 156 real
commands naming the approval script and 8 edge cases.

Changes what the guard blocks: **no**, unless you switch the channel on. The
two template suffixes stop refusals of `.env.beispiel` / `.env.vorlage`.

## 2026.10.01-7

### Security — ways to root and around the commit hooks in the example rules

The code caught all of these with the maintainer's rules; the rules shipped to
new installations did not. Measured against 2026.10.01-6 with
`security-rules.example.json`, all on level 0, all ran without an approval:

- **Commit hooks switched off for one call:** `git -c core.hooksPath=/dev/null
  commit` does what `--no-verify` does. Three spellings now blocked in the
  example and the built-in fallback: `-c`, `--config-env`,
  `GIT_CONFIG_KEY_n` in the environment.
- **Root shell through `sudo find`:** `find` is on the allowlist for searching,
  and `-exec` hands a root shell to anything. Searching stays free; the
  actions that run or write — `-exec`, `-execdir`, `-ok`, `-okdir`, `-delete`,
  `-fprint*`, `-fls` — now need an approval, like `systemctl start` already did.
- **Root writes below `/etc`:** the example protected four files there, so
  `sudo tee /etc/cron.d/x` and `sudo cp x /etc/sudoers.d/x` ran. `/etc` is
  protected as a whole now, as announced in 2026.10.01-3.
- **`/usr/local/bin` and `/usr/local/sbin`** are protected — a file there
  shadows the system command for every later call (`sudo mv x
  /usr/local/bin/ls` ran).

The built-in fallback (no rules file) also gets what the example or the
maintainer's rules already had: `/usr/local/bin`, `/usr/local/sbin`,
`chgrp -R` on system paths, `~/.npmrc` and `~/.docker/config.json`.

New test `tests/test_example_rules_root_paths.py` — 8/24 before, 24/24 after;
16/16 mutations killed, each on the expected case. One older case moved:
"a grant on `/etc` is too broad for `/etc/fstab`" assumed the file-level entry;
the same rule is now pinned with `/usr` above `/usr/bin`.

Changes what the guard blocks: **yes**, for new installations — your existing
rules file is not touched by an update; copy the entries over if you want
them. Replayed over 5,911 real commands with sudo, a system path or the hooks
setting: **101 newly blocked, 0 newly allowed.** Nearly all are probes of
exactly these holes; real work among them: two `sudo find … -exec` on a
server, one deploy into `/usr/local/bin` on a server, and three commit or log
messages that name a path under `/etc`.

Not changed, and worth deciding for yourself: `apt` and `apt-get` stay on the
example allowlist. `sudo apt-get install ./x.deb` runs a package's install
scripts as root.

## 2026.10.01-6

### New rule section — trees that must not be deleted as a whole

- `blocked_recursive_delete` names tree roots — your most valuable directories
  below the home directory, say `~/Projects` or `/mnt/data`. The fixed rule
  protects only `/` (and its first level) and `~` itself, because
  `rm -rf ~/something` is everyday work; so `rm -rf ~/Projects`,
  `mv ~/Projects /tmp/gone` and `find ~/Projects -maxdepth 1 | xargs rm -rf`
  ran without an approval. `blocked_paths_delete` is no answer there: it
  protects every single file in the tree.
- Same two steps as for `/`: the root itself blocks with every delete verb,
  one level below it only a recursive delete does, from two levels down the
  rule is off. Globs count (`rm -rf ~/Proj*`). Single files, writing and
  editing stay free. Level 1+ with a matching `allowed_paths` entry lifts it;
  the refusal has its own message.
- The section is **optional** and **empty in the example rules** — the right
  roots depend on your machine. Without it nothing changes; an older rules
  file gets the once-per-session note that the section is not configured.
- New test `tests/test_configured_tree_roots.py` — 7/20 before, 20/20 after;
  5/5 mutations killed, each on the expected case.

Changes what the guard blocks: **only if you add roots.** With the example
rules, replayed over 9,107 real commands with a delete verb: 0 differences.
With the maintainer's four roots: 78 commands hit, identical to the
maintainer's own copy, where the rule has run since 2026-08-25.

## 2026.10.01-5

### Security — an environment file named inside interpreter inline code

- `python3 -c "print(open('config/prod.env').read())"` ran without an approval,
  while `cat config/prod.env` is refused. The inline-code check used a pattern
  of its own over the whole command line and never asked
  `check_env_file_read` — so the `name.env` form (docker compose `env_file`)
  was unknown there.
- The other side of the same split: templates were refused inside inline code
  (`open('.env.example')`), and even after it — `python3 -c "…" .env.example`
  or `python3 -c "…" && git add .env.example` needed an override.
- The inline check now takes every quoted string of the inline code that
  contains the suffix and asks `check_env_file_read` — one rule for the token
  scan and the inline code.
- New test `tests/test_env_file_in_inline_code.py`, both directions — 10/15
  before, 15/15 after; 4/4 mutations killed, each on the expected case.

Changes what the guard blocks: **yes**. Replayed against the maintainer's audit
log: 276 commands with inline code and the suffix → **1 newly blocked**, a
Python heredoc searching for the text `"shell.env"` (the same rule refuses
`cat shell.env`); **2 newly allowed**, both `git add .env.example` behind a
`python3 -c`.

## 2026.10.01-4

### Security — the directory read gate behind a word it does not know

- Handing a credential directory to a recursive reader (`tar czf x ~/.ssh`,
  `find /etc … -exec cat`) is refused. But the gate looked for the reading
  command only after a fixed list of wrappers (`sudo`, `env`, `nice` …) and
  skipped the whole segment when the first word was not on it. So all of these
  ran without an approval: `timeout 60 tar czf x ~/.ssh`,
  `timeout 5 find /etc -name shadow -exec cat {} \;`, `nice -n 10 tar …`,
  `xargs tar …`, `bash -c 'tar … ~/.ssh'`, `echo $(tar czf - ~/.ssh)`,
  `for f in a; do tar … ~/.ssh; done`, `if grep -r key ~/.ssh; then …`,
  `find ~/.ssh | xargs tar czf x`, `git grep --no-index key ~/.ssh` — 23
  measured forms.
- Now a missing list entry costs a false alarm instead of a hole: when the gate
  does not know the word that leads a segment and a reading command appears in
  it, every argument of that segment counts — and those of segments piping into
  it. A segment LED by a reading command stays as precise as before, so a filter
  in a pipe (`find ~ … | grep -v cache`) remains free. Command and process
  substitution (`$(…)`, `` `…` ``, `<(…)`) open a new command position.
- The two wrapper lists (read gate; remote, container and owner-only checks)
  are one list now.
- New test `tests/test_read_gate_behind_wrappers.py`, both directions — 10/33
  before, 34/34 after; 6/6 mutations killed, each on the expected case.

Changes what the guard blocks: **yes**, the 23 forms above. Replayed against
the maintainer's audit log: 50,961 commands with a reading word, 3,671 of them
with different read targets → **3 newly blocked**, 0 newly allowed. The three:
a grep pattern `'~/'` inside `$(…)` (the same false alarm a plain
`grep -c '~/' file` already had), `find /home/<user> … | xargs grep` (reads
files from the home directory — correct), and a Python heredoc whose text names
`tar "$HOME/.ssh"` (an interpreter body is code, not text).

## 2026.10.01-3

### Security — three detours around the write guard

- **Traversal target in Write/Edit.** The write gate compared the target with
  `expand_path` only: `/tmp/../boot/x`, `/var/../usr/bin/x`,
  `/opt/x/../../sbin/x` were written without any approval. The target is now
  normalised (`_norm_path`), as the read gate already did.
- **Backslash in front of a path.** The shell turns `\/boot/x` into `/boot/x`;
  the backslash was not a valid path start, so `cp x \/boot/x` and
  `echo x > \/boot/x` ran through. It is one now.
- **Unset variable in front of a path.** `cp x $UNSET/boot/x` writes to
  `/boot/x` — the variable is empty. The comparison saw a word character in
  front and took `/boot` for the tail of another path (`${UNSET}/boot` was
  always caught). Every segment is now also checked the way the shell sees it:
  variables the line does not set are empty, `$HOME` is the home directory,
  loop and `read` variables stay. Only checked in addition — no new hole is
  possible, at most a false positive. The same gap was in the maintainer's own
  copy and is closed there too.
- New test `tests/test_write_target_detours.py`, both directions — 3/6 before,
  6/6 after; 5/5 mutations killed, each on the expected case.

Changes what the guard blocks: **yes**, the three detours. Replayed against the
maintainer's audit log: 146 allowed calls with a traversal target or a
backslash path → **16 newly blocked, all probe paths** (`/tmp/../etc/passwd`,
`/var/../home/<user>/.ssh/authorized_keys` …), 0 ordinary work. 15,334
allowed commands with a variable → **0 newly blocked**.

Also worth knowing: the example rules protect five files under `/etc`, not
`/etc` as a whole. `sudo tee /etc/cron.d/x` is not refused by the example
rules — add `/etc` to `blocked_paths_write` if that matters to you. A later
release will make that the default.

## 2026.10.01-2

### Security — `docker exec` / `run` / `attach` / `cp` on another machine need an approval

- Locally these four stay free — test runs and throwaway containers are
  everyday work. On another machine stands the production system. In the
  maintainer's own setup a remote call, inside it an `exec` into the service
  container, inside that a Python process, deleted rows from a production
  database without any approval (2026-08-18). The maintainer's copy has
  refused that shape since; this release brings it here.
- Remote means: `ssh` / `mosh` at the command position, also behind a
  wrapper (`timeout 5 ssh …`, `nice ssh …`); a container call with its own
  target (`-H`, `--host`, `--context`); and the quoted text behind `ssh`,
  `eval` or `sh -c`.
- That quoted text now ends at the **same** quote it started with. Ending at
  any quote turned `ssh h "echo 'x'; docker exec db rm -rf /data"` into
  `echo ` and judged the rest as a local command. An unclosed quote takes the
  rest of the line.
- Measured against 2026.10.01 with the example rules — all of these ran
  **without any approval**: `ssh prod "docker exec db ls"`,
  `ssh prod docker cp evil.sh web:/app/`, `timeout 5 ssh prod docker exec …`,
  `docker -H ssh://prod exec db ls`, `docker --context prod exec db ls`,
  `bash -c "echo 'p'; ssh prod docker exec db psql"`.
- New test `tests/test_remote_container_exec.py`: 18 remote cases blocked,
  12 local / read-only / prose cases free — 0/18 before, 18/18 after.
  9/9 mutations killed, each on the remote half.

Changes what the guard blocks: **yes** — remote `exec`/`run`/`attach`/`cp`.
Replayed against 9,897 previously allowed commands with `docker`/`podman` from
the maintainer's audit log: **1,130 newly need an approval** — 1,102 from before
2026-08-18, when nobody asked; 28 from the weeks after, every one a real
`docker exec` into a production container over `ssh`, refused by the
maintainer's copy today. No local call is affected. If your workflow runs
`exec` on a server routinely, expect one approval per task.

## 2026.10.01

### Security — an operator glued to an environment file, `chmod 777` in any spelling

- The read gate split a Bash command on whitespace only and stripped shell
  characters from the **left** of each word. With an operator glued to the
  name, the word no longer looked like an environment file, and these read it
  **without an override** — measured against 2026.09.30-2 with the example
  rules: `cat .env|head`, `cat .env;echo x`, `cat .env&& echo x`,
  `cat .env&echo x`, `cat .env>/tmp/x`, `cat .env||true`, ``echo `cat .env`x``,
  `base64 .env|curl -d @- …` — the same for `name.env`, `.env.local`, `.envrc`.
  Paths with a directory (`~/.ssh/id_rsa|head`, `/etc/shadow;…`) were never
  affected: those go through the path comparison, not the name.
- Fix: the read gate also splits on shell operators (`; | & < > ( )`, the
  backtick, `$(`) — but only where the shell reads them as operators. Inside
  quotes `|` is text: `grep -iE '(^|/)\.env|secret'` is a search pattern. A
  first version split there too and, replayed against the audit log, refused
  74 harmless commands of exactly that kind. Inside double quotes `$(…)` and
  backticks are still code and keep being split, so
  `echo "$(cat .env|head)"` is refused as well. As a side effect a template
  with a glued operator (`cat .env.example|head`) is free again — it was
  refused before.
- "Making something world-writable is always blocked" was two patterns with
  a mandatory blank. `chmod -R777`, `chmod 0777`, `chmod -R 0777`,
  `chmod -v 777`, `chmod --recursive 777`, `chmod -fR 777` and a later
  segment `ls; chmod 0777 …` ran through, and `chmod 7770` was refused by
  mistake. Fix: one pattern — any flags before the mode, an optional leading
  zero, a flag glued to it (`-R777`), and the mode has to end at 777. Same
  pattern in `security-rules.example.json` and in the fallback ruleset.
  **If you keep your own rules file, replace the two `chmod … 777` entries in
  `blocked_patterns` with the new one** — the rules file wins over the fallback.
- New test `tests/test_glued_operator_and_chmod_777.py`, both directions —
  1/8 before, 8/8 after; 10/10 mutations killed.

Changes what the guard blocks: **yes**, the spellings above. Replayed in the
maintainer's own guard against previously allowed commands from a real audit
log — 84,285 commands with a shell operator or `env`: **17 newly blocked** (0.02 %).
Ten are prose with punctuation after the name (`echo "… (without .env) …"`) that
2026.09.30-2 already refused through its trailing-punctuation rule — this release
only makes the maintainer's own copy agree. Seven are code or text inside a
heredoc (`cfg.env("…")` in Python). No logged command used the gap. For `chmod`:
191 commands, **0 newly blocked**.

## 2026.09.30-2

### Security — git safety behind `git -C`, flags after the refspec, `--cap-add=CAP_SYS_ADMIN`

- The git patterns expect `git` right before the subcommand. With a global
  option in between, the whole "always blocked" git group ran through
  without any approval — measured against 2026.09.30 with the example rules:
  `git -C <path> reset --hard`, `git -C <path> push --force`,
  `git -c k=v commit --amend`, `git -C <path> commit --no-verify`,
  `git -C <path> config user.name x`, `git --no-pager reset --hard`.
- Git also takes options **after** the refspec: `git push origin main --force`
  is a force-push to main and passed both the git-safety and the dedicated
  force-push rule.
- `git add` on the whole tree was recognised in two spellings only:
  `./`, `.//`, `-- .`, `-v .`, `:/` and `-v -A` passed.
- `--cap-add` was a substring check with two spellings per capability:
  `CAP_SYS_ADMIN`, two blanks, quotes, `cap_all` and a comma list passed.
- Fix, without touching the rules file: the git patterns are matched against
  the raw command **and** a normal form of it — global options removed,
  `git push` flags in front, a whole-tree `git add` written as `git add .` /
  `git add -A`, and a reading `git config <key>` (one argument, no write
  flag) written as `git config --get <key>` so that reads behind `-C` stay
  free. Capabilities are matched as a value.
- New test `tests/test_git_normal_form_and_cap_add.py`: 47 cases, both
  directions — 18/47 before, 47/47 after. 15/15 mutations killed.

Changes what the guard blocks: **yes**, the spellings above. Replayed in the
maintainer's own guard against 12,215 previously allowed commands containing
`git` or `cap-add` from a real audit log: **0 newly blocked**. (A first
version without the `git config` read rule cost 4 real reads — that rule
exists because of them.)

## 2026.09.30

### Security — deleting the root or the home directory, in any spelling

- The only barrier was the pattern `rm\s+-rf?\s+/` in `blocked_patterns`:
  exactly one spelling. Measured against 2026.09.29-4 with the example rules,
  these ran through **without any approval**: `rm -fr /`, `rm -r -f /`,
  `rm --recursive --force /`, `rm -R /`, `/*`, `/.`, `//`, `-- /`,
  `--no-preserve-root /`, `find / -delete`, `echo go; rm -fr /` (a delete in a
  later segment), the spelled-out home directory, `rm -fr ~`, `rm -fr $HOME`,
  `mv <home> /tmp/x`, and `rm -fr /home`, `/usr`, `/opt`, `/etc`.
- Four causes: the normalised root `/` is the empty string and was read as
  "no target"; no rules file names `/` or the home directory; a segment after
  `; ` kept its leading blank, so the verb pattern never matched it; and
  `--recursive` did not count as recursive.
- New fixed rule, independent of the rules file: `/` or the home directory
  **itself** is refused at every level, also with an approval (only the owner
  via `!`). A recursive delete **one level below `/`** needs level 2.
  `rm -rf ~/something`, single files, `find` without a delete action and
  relative targets stay free.
- New test `tests/test_root_and_home_delete.py`: 38 commands × two rule sets
  (as shipped, and with every `rm` pattern stripped) × levels 0 and 2 —
  64/152 before, 152/152 after. 11/11 mutations killed.
- Known limit: a relative target after `cd /` is not resolved against the
  working directory yet (README, Known limitations).

Changes what the guard blocks: **yes**. Commands that delete or move `/`, the
home directory or a first-level directory like `/usr` are now refused. The
same rule, replayed in the maintainer's own guard against 7,578 previously
allowed delete commands from a real audit log, blocked 6 more — `rm -rf` of
`/usr`, `/var`, `/lib`, `/opt`, `/home/*` and `/mnt/*`, all of them guard
probes. No everyday command was affected.

## 2026.09.29-4

### Security — opencode 2 ran without the guard

- opencode 2 loads plugins only in a new format (a directory, an Effect
  program, refusal through `Tool.Error`) and renamed its tools (`bash` →
  `shell`, `apply_patch` → `patch`, `filePath` → `path`). The 1.x plugin is
  not loaded at all — measured against 2.0.8, it stays silent. Anyone who
  updated opencode kept a plugin that checks nothing.
- New: `opencode/v2/`, an adapter for opencode 2. It maps `shell`, `read`,
  `write`, `edit`, `patch`, `grep`, `glob`, `webfetch`, `websearch` and MCP
  tools onto the guard, lets `skill`, `question` and `subagent` through (a
  subagent's own calls reach the hook one by one — measured), and **refuses
  `execute` and every unknown tool**. Code Mode reaches the network and 44
  built-in browser tools that cannot be checked one by one.
- Every path reaches the guard absolute, so a bare `prod.env` relative to the
  project is recognised as a path.
- Measured with a stand-in model (`opencode/live/`): 9/9 live, 42/42 cases,
  21/21 mutations killed. The same cases through the 1.x plugin: 23 of 24
  blocking cases pass.

Changes what the guard blocks: yes, **if you use opencode 2**. Install
`opencode/v2/` and list it under `plugins` — see `opencode/README.md`. The
1.x plugin stays for opencode 1.x. Claude Code is not affected.

## 2026.09.29-3

### Security — a redirection or quotes no longer get a command past the sudo allowlist

- Since 2026.08.27-2 the sudo check stopped at the first shell operator it
  saw, redirections included. But a redirection does not end a command — the
  shell allows it anywhere, before the command name too. So
  `sudo 2>/dev/null <anything>` ran whatever followed with raised rights, past
  the allowlist. The same held for a name in quotes (`sudo "systemctl" stop …`)
  and for a redirection glued to the name (`sudo systemctl>/dev/null stop …`
  skipped the subcommand check).
- The words after sudo are now read as the shell runs them: quotes and
  backslashes removed, redirections dropped together with their target (and a
  descriptor number like the `2` in `2>&1`), and the command ends only at
  `;`, `|`, `&`, `&&`, `||`, parentheses or a newline.
- In the other direction, `sudo -S -v; echo done` and `sudo -v;echo done` are
  no longer refused: `echo` runs without raised rights.

Changes what the guard blocks: yes. **Update** if you rely on the sudo
allowlist.

### Visible — clearer refusal texts

- An interpreter one-liner that names a self-protected path is refused even
  when it only reads. The refusal said "write access" — it now says a
  one-liner named the path, and that `cat` or `grep` reads it.
- The German update notice still claimed the changes were "almost always
  security fixes"; it now points to this file, like the English one. Both
  German update texts now use proper umlauts.

Changes what the guard blocks: no.

### Security — startup files moved by the environment are protected too

- The shell's startup files were protected at their fixed places only. With
  `ZDOTDIR` (zsh), `ENV` (sh), `BASH_ENV` (bash) or `XDG_CONFIG_HOME` (fish)
  set, the shell reads its startup code from somewhere else — a file nobody
  protected. The guard now reads these variables from its own environment and
  protects their targets **as well**. Never instead: setting a variable to a
  harmless value does not free `~/.zshrc`.
- Only absolute values or values starting with `~` count. `ENV` is a common
  name (`ENV=production`), and a relative value says nothing about where the
  shell looks. A directory in `ENV` or `BASH_ENV` is skipped — a startup file
  is a file.
- Reading stays free, as for the fixed startup files.

Changes what the guard blocks: yes, but only if one of the four variables is
set in the environment the guard runs in. If none is set, nothing changes.

## 2026.09.29-2

### Visible — the prompt-injection warning now reaches the model

- The warning went to stderr only. For a call the hook allows, Claude Code
  sends that to its debug log, so nobody saw it. It now travels through
  `additionalContext`, in the same JSON object as the rules notice, and asks
  the model to check where the instruction came from. It comes on every call
  that trips it, not once per session — it is about that command.
- Keywords now match as **whole words**, and an all-caps keyword (an acronym)
  only in capitals. `override` is gone from the example list: it is the
  guard's own approval vocabulary. Measured on 204,087 allowed commands from
  the author's audit log: the old matching would have told the model 3,726
  times in 340 sessions, real injections among them: none. The new one: 31
  times in 8 sessions, all from work on injection detection itself.
- **If you copied the example earlier**, your rules file still lists
  `override`. Remove it by hand — updates never touch your rules file.

Changes what the guard blocks: no. It changes what the model is told.

## 2026.09.29

### Security — environment files named `name.env` were readable

- The read protection matched `.env`, `.env.*` and `.envrc`, but not the form
  docker compose reads through `env_file:` — `billing-db.env`, `mail.env`,
  `api-keys.env`. `cat config/prod.env` ran free, over ssh too, and so did the
  Read tool. The function's own docstring had promised ".env at the end of the
  filename" all along. It now holds.
- `process.env` and `import.meta.env` are code, not files, and stay free.
  Templates (`prod.env.example`) stay free as before.

Changes what the guard blocks: yes. Measured on the author's audit log (210k
allowed Bash calls): 228 calls in 48 sessions would now need a level-1
override, against 1678 env denials that already happened. They mix real reads
of key files with the same prose false positives `.env.local` already has —
a file name mentioned in a search pattern, a test file the agent just wrote.

## 2026.09.23-2

### Security — the Grep tool read past every read protection

- **Not wired.** The example settings had no PreToolUse matcher for `Grep`, so
  the hook never saw it. Grep prints file contents: a private key or a `.env`
  file was one search away, whatever the rules said. `settings.example.json`
  now has eight matchers. **If you installed earlier, add the `Grep` matcher to
  your own settings** — updating the hook does not touch them.
  `tools/verify-install.py` reports it when it is missing.
- **Not closed once wired.** The hook compared Grep's path by prefix, as it does
  for Read: a key file was caught, its directory was not. Grep on the key
  directory, on the cloud-credentials directory, on the whole home directory,
  or on a project with a filter for `.env` files passed — while `grep -r` on
  the same directory in Bash was refused. A Grep call is now translated into
  its Bash counterpart and judged by the same recursive-read check; there is
  one rule, not two. The search pattern plays no part: what is searched for
  does not change what is read.
- Glob stays free. It lists names, like `ls`, and reads nothing.

Changes what the guard blocks: yes, for Grep. Cost could not be measured on
real calls — none of 83 available session transcripts from the author's
installation contains a Grep call. The rule itself is the one Bash has applied
to `grep -r` for weeks.

## 2026.09.23

### Security — a missing rules section switched its protection off

- Updates add sections to `security-rules.example.json`; your rules file is
  never touched (it is self-protected). With one section missing, its
  protection was simply gone: a hard git reset, the approval script, delete
  protection, credential reads and MCP writes all ran free on an older rules
  file. With the rules file missing entirely, MCP writes ran free too — the
  fallback ruleset had no MCP part.

  Now a **missing** critical section takes the built-in default, the same one
  the fallback uses; `mcp_policy` is new there and equals the example file. An
  **explicit** entry is kept, even an empty one — that is how you turn a
  section off on purpose. See INSTALL.md, section F, "After an update".

Changes what the guard blocks: yes, but only on rules files that lack a
section — a file with every section behaves exactly as before. Cost of the MCP
default, measured on 3119 real allowed MCP calls from an installation that has
the section: 45 would need an override without it, all code execution.

### Visible — what the rules file lacks now reaches someone

- The hook tells the model once per session which sections are missing, and
  asks it to tell you. Before, the only message was "FALLBACK ruleset active"
  on stderr — which, for a hook that allows the call, goes to Claude Code's
  debug log and nowhere else. It now uses `additionalContext`, the one
  documented channel for that case, and sets no permission decision. Other
  tool chains do not read it; `verify-install` covers them.
- `tools/verify-install.py` lists the sections the example file has and yours
  lacks. It used to count keys.

### Hardening — the update checker (merged earlier, released now)

- `update-check.py` took HOME from `$HOME`; it now reads the password
  database, like the guard. Its three environment switches are ignored at the
  installed location, like the guard's. `settings.example.json` carries the
  SessionStart entry, so merging the example wires the checker in.

## 2026.09.22-3

### Security — curl and wget slipped past write-, self- and read-protection

- **Downloader output was not a write.** The write gate knew write verbs,
  redirects, awk, `find -delete`, rsync, git clean and remote copy, but no
  downloader output flag (`-o`, `-O`, `--output`, `--output-document`, `-P`,
  `--directory-prefix`). Such a command was judged read-only, so neither
  `blocked_paths_write` nor the hardcoded self-protection list was consulted.
  The worst case: a file dropped straight into the active override directory,
  taking the approval channel with it. The output flag's ARGUMENT is now a
  write target; the URL never is, so a protected path inside a URL stays free.
  A target that is an assignment on the same line is resolved; a target that
  stays an external variable names no protected literal and is a named
  remainder, the same boundary the interpreter write guard draws.
- **`--option=PATH` hid a path from the read gate.** Tokens starting with `-`
  were skipped whole, so a credential path behind `--upload-file=` or
  `--post-file=` was never checked. The value after the first `=` is now a
  path candidate.
- **A leading `@` hid a path from the read gate.** curl reads a file given as
  `@path`; the normalisation did not strip the `@`, so `@.env` or a home path
  with `@` in front passed. A leading `@` is now stripped for every command,
  not as a curl special case.

Changes what the guard blocks: yes, only in the direction of blocking these
three forms. Measured against 12,268 real commands from an audit log that
touched a downloader or a read option: 0 newly blocked. The first version of
the fix did block two there (a protected path in nearby text) and was narrowed
before merge. 36 cases, bypass forms and controls, pinned in
`test_downloader_write_target.py` and `test_read_option_normalization.py`.

## 2026.09.02-2

### Security — the same hole one level down: `os.open`

- `os.open` takes FLAGS instead of a mode string, so the verb list from
  2026.09.02 did not match it and a one-liner using it still wrote past
  `blocked_paths_write`. Found by measuring the **remainder** after the fix was
  already in place, rather than assuming the list was complete — which is the
  point: a danger list is never finished, it is measured.

  Only the writing flags count. `os.open(path, os.O_RDONLY)` is a read and
  stays free; matching the bare function name would block reads too, which is
  "naming is enough" at a new spot. Both directions are pinned as test cases,
  and a mutation that drops the flag requirement turns the read case red.

  Still out of reach, and now stated rather than left to be discovered:
  a one-liner that hands the write to a shell through `subprocess` with
  `shell=True`, a path assembled from two string literals, and a script
  executed from a FILE instead of inline. The first is a pass-through concern,
  the second is the obfuscation boundary named in the threat model, the third
  is outside what an inline check can see.

## 2026.09.02

### Security — an interpreter one-liner wrote past `blocked_paths_write`

- `python3 -c "open('/etc/x','w').write('x')"` passed, while `echo x > /etc/x`
  was blocked and `python3 -c "os.remove(...)"` on a delete-protected path was
  blocked too. Every path in `blocked_paths_write` was reachable this way, the
  key directory included — the very class this guard was built against.

  The cause was an asymmetry rather than a missing entry: `_command_deletes`
  has carried its inline counterpart (`_DELETE_INLINE_RE`) from the start,
  `_command_is_write` never had one. Pre-existing, measured against nine
  variants and against an older edition: identical picture.

  What gets checked are the **targets** of the write, not the whole one-liner.
  A protected path used as a read source, or appearing as text in the content
  being written, is not a target. That distinction is the fix, not a detail:
  the blanket form ("naming is enough", as self-protection uses it) costs 47
  genuine false positives across 32 sessions when applied to this list,
  because it holds system directories that appear in every shebang. Measured
  against 220748 real commands from an audit log: **1 newly blocked** (a probe
  of our own), **0 newly released**.

  If the target cannot be read as a literal — a variable, an f-string — the
  check falls back to the whole block (fail-closed), so moving the path into a
  variable is not a way around.

  Delete protection is explicitly excluded from this branch: an `open(...,"w")`
  under a delete-only path is allowed, and treating the two lists alike would
  turn one into the other.

  `tests/test_inline_write_target.py`, 19 cases, 10 of them red before.

### Documentation

- INSTALL.md never mentioned the `VERSION` file. Following the instructions to
  the letter produced an installation whose update check is silent — and since
  2026.08.29-2 the installation checker warns about exactly that, so the reader
  got a warning the instructions did not explain. Measured on the author's own
  machine, where the check had been quiet for days for this reason. The copy
  step, the file table and the update-check section now name it.

## 2026.08.30-3

### Changed — the guard, without changing a verdict

- The targets a command touches are collected in ORDER now, not through a set.
  Python randomises set iteration per process, so with two writing segments the
  order of the collected targets changed from run to run. The verdict never
  depended on it — every target has to be covered, which is order-independent,
  verified across five hash seeds — but the message picked `targets[0]`, and in
  the edition that still did so the same command produced different advice on
  different runs (measured 2026-08-30: five of twelve runs disagreed). Since
  2026.08.30-2 the message names the uncovered target and no longer depends on
  order at all; this makes the remaining fallback stable too. Hardening, not a
  fix for a defect measurable on main.

## 2026.08.30-2

### Fixed — the message, not the verdict

- A refusal named the FIRST target it had found, not the one the grant fails to
  cover. With a grant on one directory and a write to its neighbour in the same
  line, it advised "you need an allowed_paths grant for <the directory already
  granted>" — following that advice changes nothing. The verdict was right and
  its explanation sent the reader in a circle. Measured live on 2026-08-30; the
  refusal now names the uncovered target. Nothing about what is blocked changes.

## 2026.08.30

### Fixed — the guard

- **security-adjacent (false positive)** — The target extraction added in
  2026.08.29 read the WHOLE command line, while the path match reads only the
  segments that write. A reading segment naming the protected parent therefore
  poisoned the verdict: `rm -rf <granted dir> && ls <parent>` was refused
  although nothing outside the grant is written. The guard has drawn that
  segment boundary since 2026.08.20; the new function was walking around it.
  Both now use one shared helper, so they cannot drift apart again. Found by a
  live probe against the sharp installation, not by the suite — no test case
  named a protected path in a reading segment while holding a grant.

## 2026.08.29-2

### Fixed — the guard

- **security** — The fallback ruleset said "fail-closed" and left three things
  out. With the rules file missing, `owner_only_commands`, `blocked_git_ops` and
  `blocked_paths_delete` were simply absent, so the approval scripts became
  ordinary commands, `git reset --hard` and `--no-verify` ran, and the tool
  chain's transcripts and memory could be deleted. Worse as a chain: the rules
  file's parent directory is not protected, the pending directory is open by
  design, and the approval script was the third step — three allowed operations
  and the assistant holds a level-2 grant, with the guard printing "FALLBACK
  ruleset active (fail-closed)" throughout. All three keys are now in the
  fallback. Reported 2026-08-29 by an external review.

### Fixed — the tools, not the guard

- `tools/verify-install.py` now checks the three places where an installation
  is wrong and **nothing complains**: `update_check.enabled` on with no
  SessionStart hook running the checker; a missing `VERSION` file next to the
  hook (the checker then stays silent, which is indistinguishable from "you are
  up to date"); the assistant's rules document; and the proposal directory,
  without which the documented approval path ends in an error the owner never
  sees. Silent when the update check is off — a tool that nags about a feature
  nobody switched on is not read when it matters.
- `tools/would-it-help.py` pointed at a "setup dialogue" that does not exist
  anywhere in the repository. It now names the rules file and the configuration
  reference.

### Documentation

- The README claimed `sha256sum <protected file> > /tmp/sum.txt` is refused.
  Measured: it runs — the redirect target is what counts. Copying *onto* a
  protected path with a harmless redirect appended is still refused. The
  documented false positive had been fixed and the text never followed.
- Level 1 now says what a grant covers: what it names and what lies below it,
  not the directory above.
- The approval channel section covers session binding and `--all-sessions`.
  Without it, following the README literally produces an error the README does
  not explain — and other tool chains, which may not export
  `CLAUDE_CODE_SESSION_ID`, hit it every time.

### Changed — the example rules

- `blocked_paths_delete` now also lists the guard's own directories
  (`~/.claude/hooks`, `bin`, `rules`, `safety-guard`). Self-protection covers
  the FILES in them; naming the DIRECTORY removed them as a side effect — the
  documented ancestor-delete limitation, applied to the rules file itself.
  Measured over 216,972 real commands: 88 delete forms hit `~/.claude/hooks`, 1
  of which had been allowed.

## 2026.08.29

### Fixed — the guard

- **security** — A level-1 grant covered more than it named. `check_blocked_paths`
  reports which LIST ENTRY matched, and that entry — not the path the command
  actually touches — was what the grant was checked against. A grant on
  `~/.ssh/config.d` therefore opened all of `~/.ssh`: `authorized_keys`, the
  private key, `rm -rf ~/.ssh`. On an installation whose rules list directories
  (`/etc`, `/opt/inox`) rather than single files, a deployment grant on one
  service opened every other service and the recursive delete of the whole tree
  — the exact operation level 1 says it does not allow. The grant is now checked
  against the concretely touched target, and against the DEEPEST list entry that
  covers it, so a grant on a zone no longer swallows a more specific entry
  below it (`/etc` no longer covers `/etc/shadow` when both are listed).
  Reported 2026-08-29 by an external review, measured on both editions.

## 2026.08.27-3

### Fixed — the guard

- **security** — The shell rewrites a command after the guard has read it, and
  self-protection was reading the spelling that never executes. Empty quote
  pairs (`~/.claude/set''tings.json`) and brace lists
  (`~/.claude/{settings,x}.json`) both reached protected paths that the plain
  spelling could not — no tool, no encoding, no override. Both are undone
  before any check now, along with the IFS splitting that was already handled.
  Globbing is deliberately *not* expanded: its result depends on the
  filesystem, so a pattern is held against the protected list unexpanded
  instead.


### Fixed — the tools, not the guard

- **security (reporting)** — `tools/verify-install.py` never read the `matcher`
  field. An installation registering the guard for `Bash` alone, leaving
  `Read`, `Write`, `Edit`, `MultiEdit`, `NotebookEdit` and the `mcp__*` family
  unguarded, was reported as `12 ok, 1 to look at, 0 broken` with exit code 0.
  The behavioural probes cannot see this: they drive the hook directly, so they
  prove what it decides, never whether it is asked. The matcher coverage is now
  checked — accepting an absent or empty matcher, which covers every tool and
  is the safest configuration there is.
- `verify-install.py`: all registered entries are checked for their file, not
  just the first; a mismatch between the interpreter in `settings.json` and the
  one running the probes is reported; a half-present approval channel no longer
  passes in silence; `--strict` lets warnings decide the exit code.
- **`tools/would-it-help.py` counted this repository's own probes as evidence.**
  `verify-install.py` writes to the real audit log by design, and six in ten of
  its probes are blocks. On a fresh installation those were the entire sample,
  and the report concluded "60 % would have been stopped — expect real
  friction" from its own test material. Own sessions are skipped now, and below
  30 commands no rate is printed at all.
- `would-it-help.py`: the exposure scan looked in six directory names. Work in
  `~/git`, `~/repos`, `~/workspace` or a writable system location counted as
  "nothing found", which the verdict turned into advice against installing.
  Eleven names now plus writable system locations, package directories skipped
  (0.3 s over five locations, against 4.0 s over one before), and an empty
  result says where it looked.
- `would-it-help.py`: `--yes` no longer swallows the notice about what will be
  read.

### Fixed — tests

- Four test files gave different answers depending on where they were run.
  `test_relative_write_targets` needed a real `~/.claude` and died with a
  traceback without one; `test_command_position` inherited the caller's working
  directory and went red from a clone standing on `main`, where a second and
  unrelated rule applies; `test_remote_copy_and_branch_guard` needs `git` and
  `test_diagnostics_register` needs `pyright`, and both now skip instead of
  failing. The diagnostics file also detects a checkout inside a throwaway
  location, which used to turn nine cases red for a reason unrelated to the
  hook.
- `requirements-dev.txt` names what the suite needs.

### Documentation

- The self-protection table was missing `~/.claude/guard-config.json` — the
  file that says where the rules live. It **is** protected; only the table did
  not say so, which made a strength look like a hole.
- The README said "six tool matchers" where INSTALL.md said seven. Prose no
  longer counts: it points at `settings.example.json`, and a test asserts that
  file is complete.
- Blocking `git commit` on a protected branch is documented — it surprises
  people, and it reached into this project's own test suite.
- Reference sections moved to `docs/` (configuration, tool chains, diagnostics
  register, what's new in v2). The counter-test documents moved to
  `docs/counter-tests/`.
- `SECURITY.md`, `CONTRIBUTING.md` and this file added.

---

## 2026.08.27

- **security** — A single asterisk walked past the self-protection. A write
  target containing `*`, `?` or `[…]` is now held against every protected path
  component by component; patterns are never expanded, because that would make
  the verdict depend on the filesystem (#55).
- **security** — Force-push written as a `+refspec` (`git push origin
  +main:main`) was not recognised as a force-push (#64).
- Documentation: the container guard and glob matching (#56), the tool chains
  and what each covers (#54), and that the repository talks to assistants
  (#63). INSTALL.md corrected to seven PreToolUse matchers — the `mcp__.*`
  entry was missing, so MCP tool calls reached no guard on installations that
  followed it (#65).
- New: `tools/verify-install.py` (#58) and `tools/would-it-help.py` (#59, #61,
  #62), `AGENTS.md` (#60).
- Tests: check for zero failures rather than an expected case count (#57).

> Honest note: the version was bumped in #56, a documentation change, and the
> security fix #55 nine minutes earlier rode along with it. #64, a second
> security fix, landed the same day **after** the bump and was therefore never
> announced by the update check — dates cannot separate eleven commits in one
> day. That is why tags exist from here on.

## 2026.08.23

- **security** — Shell variables are resolved in the interpreter branch, so a
  protected path assembled from a variable is caught (#52).
- A refused inline one-liner now says *why*: naming a protected path, not
  writing to it (#53).

> This bump exists because five guard changes had been shipped without one.

## 2026.08.22

- **security** — Self-protection now matches a path, not a prefix, in the
  interpreter branch. While only one of the two comparison branches had the
  boundary, the guard refused the very thing it is supposed to allow: dropping
  an override proposal.
- **security** — Quoted text is not a command. Two further holes were found
  behind that question, and the first attempt at the fix — a danger list rather
  than a harmless list — tore four more, which is why the final shape is the
  other way round.
- **security** — The shell's startup files are protected. A single line in one
  of them redefines what every later command means, which is the ground every
  other check stands on.
- **security** — Antigravity's control files are protected: the third tool
  chain can execute what this one writes (#49).
- New: the diagnostics register, a second hook (#50).

> This bump exists because three merged changes had been shipped without one.

## 2026.08.21 and earlier

Before this point the version file was not maintained per change. The history
is in the commit log; the substantial entries of that day were: delete
protection as a second path list, owner-only commands matched by command
position rather than by text, redirect targets treated as writes, the adapter
contract for a second tool chain, and self-protection extended to that
adapter's own files.
