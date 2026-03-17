"""Service server that validates AES-encrypted tickets and 2-of-3 signatures."""

from __future__ import annotations

import argparse
import json
import socketserver
from datetime import datetime
from typing import Dict

from crypto_utils import DEFAULT_SERVICE_ID, HOST, SERVICE_PORTS, load_public_registry, verify_ticket_for_service


class JsonHandler(socketserver.StreamRequestHandler):
    @staticmethod
    def _ts() -> str:
        return datetime.now().strftime("%H:%M:%S")

    def _log(self, server_id: str, msg: str) -> None:
        print(f"[{self._ts()}] [{server_id}] {msg}", flush=True)

    def handle(self) -> None:
        peer = f"{self.client_address[0]}:{self.client_address[1]}"
        server_id = self.server.service_id  # type: ignore[attr-defined]
        self._log(server_id, f"CONNECT {peer}")
        try:
            raw = self.rfile.readline()
            if not raw:
                self._log(server_id, f"EMPTY_REQUEST {peer}")
                return
            try:
                req = json.loads(raw.decode("utf-8"))
            except json.JSONDecodeError:
                self._log(server_id, f"INVALID_JSON {peer}")
                self._send({"ok": False, "error": "Invalid JSON"})
                return

            action = req.get("action")
            context = ""
            ticket = req.get("ticket")
            if isinstance(ticket, dict):
                try:
                    from crypto_utils import decrypt_ticket

                    payload = decrypt_ticket(ticket).get("payload", {})
                    cid = payload.get("client_id")
                    sid = payload.get("service_id")
                    if isinstance(cid, str):
                        context += f" client_id={cid}"
                    if isinstance(sid, str):
                        context += f" ticket_service_id={sid}"
                except Exception:
                    context += " ticket_payload=unreadable"
            self._log(server_id, f"REQUEST {peer} action={action}{context}")
            resp = self.server.dispatch(req)  # type: ignore[attr-defined]
            if resp.get("ok"):
                self._log(server_id, f"RESPONSE {peer} ok=True message={resp.get('message', 'OK')}")
            else:
                self._log(server_id, f"RESPONSE {peer} ok=False error={resp.get('error', 'Unknown error')}")
            self._send(resp)
        finally:
            self._log(server_id, f"DISCONNECT {peer}")

    def _send(self, obj: Dict[str, object]) -> None:
        self.wfile.write((json.dumps(obj) + "\n").encode("utf-8"))


class ServiceServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True

    def __init__(self, server_address, service_id: str):
        super().__init__(server_address, JsonHandler)
        self.service_id = service_id

    def _load_verifier_material(self) -> tuple[dict[str, int], dict[str, int]]:
        data = load_public_registry()
        public_keys = {k: int(v) for k, v in data["public_keys"].items()}
        key_versions = {k: int(v) for k, v in data["key_versions"].items()}
        return public_keys, key_versions

    def dispatch(self, req: Dict[str, object]) -> Dict[str, object]:
        if req.get("action") != "authenticate":
            return {"ok": False, "error": "Unsupported action"}

        ticket = req.get("ticket")
        if not isinstance(ticket, dict):
            return {"ok": False, "error": "Missing ticket"}

        public_keys, key_versions = self._load_verifier_material()
        ok, msg = verify_ticket_for_service(ticket, public_keys, key_versions, self.service_id)
        if not ok:
            return {"ok": False, "error": msg}
        return {"ok": True, "message": msg}


def main() -> None:
    parser = argparse.ArgumentParser(description="Run service server")
    parser.add_argument("--service-id", default=DEFAULT_SERVICE_ID)
    parser.add_argument("--host", default=HOST)
    parser.add_argument("--port", type=int)
    args = parser.parse_args()

    port = args.port if args.port is not None else SERVICE_PORTS.get(args.service_id, SERVICE_PORTS[DEFAULT_SERVICE_ID])
    srv = ServiceServer((args.host, port), args.service_id)
    print(f"Service server started: {args.service_id} on {args.host}:{port}")
    srv.serve_forever()


if __name__ == "__main__":
    main()
