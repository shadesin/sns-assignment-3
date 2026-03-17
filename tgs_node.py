"""Ticket Granting Service Authority node process for TGS1/TGS2/TGS3."""

from __future__ import annotations

import argparse
import json
import socketserver
from datetime import datetime
from typing import Dict

from crypto_utils import HOST, TGS_PORTS, load_or_create_authority_key, schnorr_sign


class JsonHandler(socketserver.StreamRequestHandler):
    @staticmethod
    def _ts() -> str:
        return datetime.now().strftime("%H:%M:%S")

    def _log(self, server_id: str, msg: str) -> None:
        print(f"[{self._ts()}] [{server_id}] {msg}", flush=True)

    def handle(self) -> None:
        peer = f"{self.client_address[0]}:{self.client_address[1]}"
        server_id = self.server.authority_id  # type: ignore[attr-defined]
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
            payload = req.get("payload")
            if isinstance(payload, dict):
                cid = payload.get("client_id")
                sid = payload.get("service_id")
                if isinstance(cid, str):
                    context += f" client_id={cid}"
                if isinstance(sid, str):
                    context += f" service_id={sid}"
            self._log(server_id, f"REQUEST {peer} action={action}{context}")
            response = self.server.dispatch(req)  # type: ignore[attr-defined]
            if response.get("ok"):
                self._log(server_id, f"RESPONSE {peer} ok=True")
            else:
                self._log(server_id, f"RESPONSE {peer} ok=False error={response.get('error', 'Unknown error')}")
            self._send(response)
        finally:
            self._log(server_id, f"DISCONNECT {peer}")

    def _send(self, obj: Dict[str, object]) -> None:
        self.wfile.write((json.dumps(obj) + "\n").encode("utf-8"))


class TGSServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True

    def __init__(self, server_address, authority_id: str):
        super().__init__(server_address, JsonHandler)
        key_record = load_or_create_authority_key(authority_id)
        self.authority_id = authority_id
        self.private_key = int(key_record["private_key"])
        self.public_key = int(key_record["public_key"])
        self.key_version = int(key_record["key_version"])

    def dispatch(self, req: Dict[str, object]) -> Dict[str, object]:
        action = req.get("action")
        if action == "get_public_info":
            return {
                "ok": True,
                "authority_id": self.authority_id,
                "public_key": str(self.public_key),
                "key_version": self.key_version,
            }

        if action != "issue_st_partial":
            return {"ok": False, "error": f"Unsupported action: {action}"}

        payload = req.get("payload")
        if not isinstance(payload, dict):
            return {"ok": False, "error": "Missing payload"}

        signature = schnorr_sign(payload, self.authority_id, self.private_key)
        signature["key_version"] = self.key_version

        return {
            "ok": True,
            "authority_id": self.authority_id,
            "signature": signature,
        }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run TGS node")
    parser.add_argument("--id", required=True, choices=["TGS1", "TGS2", "TGS3"])
    parser.add_argument("--host", default=HOST)
    parser.add_argument("--port", type=int)
    args = parser.parse_args()

    port = args.port if args.port is not None else TGS_PORTS[args.id]
    server = TGSServer((args.host, port), args.id)
    print(f"TGS node started: {args.id} listening on {args.host}:{port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
