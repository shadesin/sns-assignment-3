"""Ticket Granting Service Authority node process for TGS1/TGS2/TGS3."""

from __future__ import annotations

import argparse
import json
import socketserver
from typing import Dict

from crypto_utils import HOST, TGS_PORTS, load_or_create_authority_key, schnorr_sign


class JsonHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        raw = self.rfile.readline()
        if not raw:
            return
        try:
            req = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            self._send({"ok": False, "error": "Invalid JSON"})
            return

        response = self.server.dispatch(req)  # type: ignore[attr-defined]
        self._send(response)

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
