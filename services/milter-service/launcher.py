from __future__ import annotations

import json
import logging
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from app.runtime import runtime_state, start_milter_server


logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")


class HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        if self.path != "/healthz":
            self.send_response(404)
            self.end_headers()
            return
        payload = {
            "status": "ok" if runtime_state.import_ok and runtime_state.running else "degraded",
            "import_ok": runtime_state.import_ok,
            "milter_running": runtime_state.running,
            "last_error": runtime_state.last_error,
        }
        body = json.dumps(payload).encode("utf-8")
        code = 200 if payload["status"] == "ok" else 503
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return


def start_health_server() -> threading.Thread:
    server = ThreadingHTTPServer(("0.0.0.0", 9901), HealthHandler)
    thread = threading.Thread(target=server.serve_forever, name="health-server", daemon=True)
    thread.start()
    return thread


if __name__ == "__main__":
    start_health_server()
    start_milter_server()
