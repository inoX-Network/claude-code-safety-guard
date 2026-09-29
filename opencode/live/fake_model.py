#!/usr/bin/env python3
"""A stand-in model in the OpenAI chat format, for measuring opencode 2.x.

Plays a fixed list of tool calls -- no real model, no cost, no network beyond
127.0.0.1. The n-th request (counted by the tool answers in the history) gets
the n-th call, after that a text answer. Every request is logged to
$FAKE_MODEL_LOG (offered tools, number of tool answers, the last one cut short).

Subagents: if a user message in the history contains the marker "child-task",
the stand-in plays $FAKE_MODEL_CHILD_CALLS instead -- otherwise the subagent
would repeat the main agent's call.

Run: FAKE_MODEL_CALLS='[{"name":"shell","arguments":{"command":"..."}}]' \
     python3 fake_model.py <port>
"""
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CALLS = json.loads(os.environ.get("FAKE_MODEL_CALLS", "[]"))
CHILD_CALLS = json.loads(os.environ.get("FAKE_MODEL_CHILD_CALLS", "[]"))
LOG = os.environ.get("FAKE_MODEL_LOG", os.devnull)
CHILD_MARKER = "child-task"


def log(entry):
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def sse(handler, chunk):
    handler.wfile.write(b"data: " + json.dumps(chunk).encode() + b"\n\n")
    handler.wfile.flush()


class FakeModel(BaseHTTPRequestHandler):
    def log_message(self, format, *args):  # noqa: A002 -- base class signature
        # access log suppressed, logging happens in log()
        pass

    def do_GET(self):
        body = json.dumps({"object": "list", "data": [{"id": "fake", "object": "model"}]}).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("content-length", 0))
        request = json.loads(self.rfile.read(length) or b"{}")
        messages = request.get("messages", [])
        answers = [m for m in messages if m.get("role") == "tool"]
        n = len(answers)
        child = any(m.get("role") == "user" and CHILD_MARKER in json.dumps(m.get("content"))
                    for m in messages)
        calls = CHILD_CALLS if child else CALLS
        log({
            "child": child,
            "tools": sorted(t.get("function", {}).get("name", "?") for t in request.get("tools", [])),
            "tool_answers": n,
            "last_answer": str(answers[-1].get("content"))[:400] if answers else None,
        })
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.send_header("cache-control", "no-cache")
        self.end_headers()
        head = {"id": f"fake-{n}", "object": "chat.completion.chunk", "created": 0, "model": "fake"}
        if n < len(calls):
            call = calls[n]
            sse(self, {**head, "choices": [{"index": 0, "delta": {"role": "assistant", "tool_calls": [{
                "index": 0, "id": f"call_{n}", "type": "function",
                "function": {"name": call["name"], "arguments": json.dumps(call["arguments"])},
            }]}, "finish_reason": None}]})
            finish = "tool_calls"
        else:
            sse(self, {**head, "choices": [{"index": 0, "delta": {"role": "assistant", "content": "done"},
                                            "finish_reason": None}]})
            finish = "stop"
        sse(self, {**head, "choices": [{"index": 0, "delta": {}, "finish_reason": finish}],
                   "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}})
        self.wfile.write(b"data: [DONE]\n\n")
        self.wfile.flush()


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), FakeModel).serve_forever()
