"""Service server that validates AES-encrypted tickets and 2-of-3 signatures."""

from __future__ import annotations

import argparse
import json
import socketserver
from typing import Dict

from crypto_utils import DEFAULT_SERVICE_ID, HOST, SERVICE_PORTS, load_public_registry, verify_ticket_for_service


class JsonHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        peer = f"{self.client_address[0]}:{self.client_address[1]}"
        server_id = self.server.service_id  # type: ignore[attr-defined]
        print(f"[{server_id}] CONNECT {peer}", flush=True)
        try:
            raw = self.rfile.readline()
            if not raw:
                print(f"[{server_id}] EMPTY_REQUEST {peer}", flush=True)
                return
            try:
                req = json.loads(raw.decode("utf-8"))
            except json.JSONDecodeError:
                print(f"[{server_id}] INVALID_JSON {peer}", flush=True)
                self._send({"ok": False, "error": "Invalid JSON"})
                return

            action = req.get("action")
            print(f"[{server_id}] REQUEST {peer} action={action}", flush=True)
            resp = self.server.dispatch(req)  # type: ignore[attr-defined]
            print(
                f"[{server_id}] RESPONSE {peer} ok={bool(resp.get('ok', False))}",
                flush=True,
            )
            self._send(resp)
        finally:
            print(f"[{server_id}] DISCONNECT {peer}", flush=True)

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
