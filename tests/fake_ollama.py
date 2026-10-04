"""A small stand-in for the Ollama HTTP API (/api/tags and streaming /api/chat), for tests."""
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class FakeOllama:
    def __init__(self, models=("qwen2.5:7b",), reply=("## Özet\n", "Sunucu ", "iyi durumda."), status=200):
        self.endless = False      # keep streaming forever, like a model stuck in a loop
        self.done_reason = "stop"
        self.models = list(models)
        self.reply = list(reply)
        self.status = status
        self.requests: list[dict] = []
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                if self.path != "/api/tags":
                    self.send_error(404)
                    return
                body = json.dumps({"models": [{"name": m} for m in owner.models]}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                data = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                owner.requests.append(data)
                if data.get("model") not in owner.models:
                    body = json.dumps({"error": f"model '{data.get('model')}' not found"}).encode()
                    self.send_response(404)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                self.send_response(owner.status)
                self.send_header("Content-Type", "application/x-ndjson")
                self.end_headers()
                pieces = owner.reply
                try:
                    while True:
                        for piece in pieces:
                            self.wfile.write((json.dumps({"message": {"role": "assistant", "content": piece},
                                                          "done": False}) + "\n").encode())
                            self.wfile.flush()
                            if owner.endless:
                                time.sleep(0.05)
                        if not owner.endless:
                            break
                    self.wfile.write((json.dumps({"done": True, "done_reason": owner.done_reason,
                                                  "eval_count": len(pieces)}) + "\n").encode())
                except (BrokenPipeError, ConnectionResetError):
                    pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
