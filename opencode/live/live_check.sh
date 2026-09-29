#!/bin/sh
# Live check: the real adapter (opencode/v2) inside a real `opencode serve`,
# driven by a stand-in model (fake_model.py) -- no real model, no cost.
#
# Fully sealed off:
#   - empty XDG directories under $1, your opencode configuration and
#     sessions stay untouched; the configuration comes in through
#     OPENCODE_CONFIG_CONTENT, no config file is written.
#   - HOME points into $1, so the protected targets (.claude/settings.json)
#     are throwaway files. The read probe uses a relative env file with dummy
#     content -- never real keys: the guard resolves ~ through the real account,
#     not through HOME, so a failed probe could read the real one.
#   - the guard is a copy from this repository; rules, overrides and audit log
#     point into $1.
# If the adapter fails, only throwaway files are hit.
#
# Run: sh opencode/live/live_check.sh <empty-directory>
# Counter-check: ADAPTER_DIR=<an empty directory> loads no adapter -- then the
# "blocked" checks must fail, or this script proves nothing.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
T=$1
ADAPTER_DIR=${ADAPTER_DIR:-$REPO/opencode/v2}
PORT=${PORT:-4199}
MPORT=${MPORT:-4299}
mkdir -p "$T/config" "$T/data" "$T/state" "$T/cache" "$T/work" "$T/home/.claude" "$T/ov" "$T/audit"
echo "DUMMY_ONLY=1" > "$T/work/prod.env"
cp "$REPO/hooks/command-guard.py" "$T/guard.py"
echo '{}' > "$T/guard-config.json"

export SAFETY_GUARD_PATH="$T/guard.py"
export CLAUDE_SECURITY_RULES="$REPO/security-rules.example.json"
export CLAUDE_SUDO_OVERRIDES_DIR="$T/ov" CLAUDE_AUDIT_DIR="$T/audit"
export CLAUDE_HOOK_DEV_FLAG="$T/no-dev-mode" CLAUDE_GUARD_CONFIG="$T/guard-config.json"
export HOME="$T/home"
export XDG_CONFIG_HOME="$T/config" XDG_DATA_HOME="$T/data" XDG_STATE_HOME="$T/state" XDG_CACHE_HOME="$T/cache"
export OPENCODE_CONFIG_CONTENT="{\"plugins\": [\"$ADAPTER_DIR\"], \"model\": \"fake/fake\", \"provider\": {\"fake\": {\"npm\": \"@ai-sdk/openai-compatible\", \"name\": \"Fake\", \"options\": {\"baseURL\": \"http://127.0.0.1:$MPORT/v1\", \"apiKey\": \"fake\"}, \"models\": {\"fake\": {\"name\": \"Fake\", \"tool_call\": true}}}}}"
export FAKE_MODEL_LOG="$T/fake-model.log"
FAKE_MODEL_CALLS=$(sed "s|@T@|$T|g" "$HERE/calls.json")
FAKE_MODEL_CHILD_CALLS=$(sed "s|@T@|$T|g" "$HERE/child_calls.json")
export FAKE_MODEL_CALLS FAKE_MODEL_CHILD_CALLS
# Throwaway password, only for this local, sealed-off run
export OPENCODE_SERVER_PASSWORD=live-check-local
AUTH="opencode:live-check-local"
URL="http://127.0.0.1:$PORT"

python3 "$HERE/fake_model.py" "$MPORT" &
MODEL_PID=$!
cd "$T/work" || exit 1
opencode serve --port "$PORT" --hostname 127.0.0.1 > "$T/serve.log" 2>&1 &
SERVE_PID=$!
i=0
until curl -s -o /dev/null -u "$AUTH" "$URL/api/session"; do
    i=$((i + 1)); [ $i -gt 60 ] && break; sleep 0.5
done
SID=$(curl -s -u "$AUTH" -X POST "$URL/api/session" -H 'content-type: application/json' -d '{}' \
    | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("id") or d.get("data",{}).get("id",""))')
curl -s -o /dev/null -u "$AUTH" -X POST "$URL/api/session/$SID/prompt" \
    -H 'content-type: application/json' -d '{"text":"live check"}'
# wait until the stand-in has played every call (main + child) and answered
i=0
while [ "$(cat "$FAKE_MODEL_LOG" 2>/dev/null | wc -l)" -le 9 ]; do
    i=$((i + 1)); [ $i -gt 60 ] && break; sleep 0.5
done
sleep 1
kill "$SERVE_PID" "$MODEL_PID" 2>/dev/null
wait "$SERVE_PID" "$MODEL_PID" 2>/dev/null

python3 - "$T" <<'EOF'
import json, os, sys
T = sys.argv[1]
answers = {}
for line in open(os.path.join(T, "fake-model.log")):
    d = json.loads(line)
    if d["last_answer"]:
        answers[("child" if d["child"] else "main", d["tool_answers"])] = d["last_answer"]
def refused(key):
    return '"error"' in answers.get(key, "")
checks = [
    ("shell, harmless: runs", os.path.exists(f"{T}/harmless")),
    ("shell writes .claude/settings.json: blocked", refused(("main", 2))),
    ("write .claude/settings.local.json: blocked", refused(("main", 3))),
    ("read prod.env (relative): blocked", refused(("main", 4))),
    ("execute: blocked", refused(("main", 5))),
    ("subagent: runs", ("main", 6) in answers and not refused(("main", 6))),
    ("subagent, harmless shell: runs", os.path.exists(f"{T}/child-harmless")),
    ("subagent writes .claude/settings.json: blocked", refused(("child", 2))),
    ("no protected file was created", not os.path.exists(f"{T}/home/.claude/settings.json")
        and not os.path.exists(f"{T}/home/.claude/settings.local.json")),
]
failed = 0
for name, ok in checks:
    failed += not ok
    print(f"  {'ok  ' if ok else 'FAIL'} {name}")
print(f"\n{len(checks) - failed}/{len(checks)} passed")
sys.exit(1 if failed else 0)
EOF
