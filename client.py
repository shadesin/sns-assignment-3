"""Client for distributed AS/TGS exchange and service authentication."""

from __future__ import annotations

import argparse
import json
import random
import socket
import statistics
import time
from typing import Dict, List, Tuple

from crypto_utils import (
    AS_PORTS,
    DEFAULT_SERVICE_ID,
    HOST,
    SERVICE_PORTS,
    TGS_PORTS,
    build_ticket_payload,
    decrypt_ticket,
    encrypt_ticket,
    schnorr_verify,
)


def send_json_request(host: str, port: int, request_obj: dict, timeout: float = 3.0) -> dict:
    with socket.create_connection((host, port), timeout=timeout) as conn:
        conn.sendall((json.dumps(request_obj) + "\n").encode("utf-8"))
        data = b""
        while not data.endswith(b"\n"):
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk
    if not data:
        raise RuntimeError(f"No response from {host}:{port}")
    return json.loads(data.decode("utf-8"))


def fetch_authority_info(authority_ports: Dict[str, int]) -> Tuple[Dict[str, int], Dict[str, int]]:
    public_keys = {}
    key_versions = {}
    for aid, port in authority_ports.items():
        last_err = None
        resp = None
        for _ in range(8):
            try:
                resp = send_json_request(HOST, port, {"action": "get_public_info"})
                break
            except Exception as exc:  # pylint: disable=broad-except
                last_err = exc
                time.sleep(0.25)
        if resp is None:
            raise RuntimeError(f"get_public_info failed for {aid}: {last_err}")
        if not resp.get("ok"):
            raise RuntimeError(f"get_public_info failed for {aid}: {resp}")
        public_keys[aid] = int(resp["public_key"])
        key_versions[aid] = int(resp["key_version"])
    return public_keys, key_versions


def collect_partial_signatures(
    authority_ports: Dict[str, int],
    action: str,
    payload: dict,
    public_keys: Dict[str, int],
    expected_versions: Dict[str, int],
) -> List[dict]:
    signatures: List[dict] = []
    for aid, port in authority_ports.items():
        try:
            resp = send_json_request(HOST, port, {"action": action, "payload": payload})
        except Exception:
            continue
        if not resp.get("ok") or not resp.get("signature"):
            continue

        sig = resp["signature"]
        if not isinstance(sig, dict):
            continue

        resp_aid = resp.get("authority_id")
        if not isinstance(resp_aid, str) or resp_aid not in public_keys:
            continue
        if sig.get("authority_id") != resp_aid:
            continue
        if int(sig.get("key_version", -1)) != int(expected_versions.get(resp_aid, -2)):
            continue
        if not schnorr_verify(payload, sig, public_keys[resp_aid]):
            continue

        signatures.append(sig)
        if len(signatures) >= 2:
            break
    if len(signatures) < 2:
        raise RuntimeError("Could not collect at least two signatures")
    return signatures


def request_tgt(
    client_id: str,
    as_ports: Dict[str, int],
    as_public_keys: Dict[str, int],
    as_key_versions: Dict[str, int],
) -> dict:
    session_key = random.randbytes(32).hex()
    payload = build_ticket_payload(client_id, "krbtgt", session_key, as_key_versions)
    signatures = collect_partial_signatures(
        as_ports,
        "issue_tgt_partial",
        payload,
        as_public_keys,
        as_key_versions,
    )
    return encrypt_ticket(payload, signatures)


def request_service_ticket(
    client_id: str,
    tgs_ports: Dict[str, int],
    tgs_public_keys: Dict[str, int],
    tgs_key_versions: Dict[str, int],
    service_id: str,
) -> dict:
    session_key = random.randbytes(32).hex()
    payload = build_ticket_payload(client_id, service_id, session_key, tgs_key_versions)
    signatures = collect_partial_signatures(
        tgs_ports,
        "issue_st_partial",
        payload,
        tgs_public_keys,
        tgs_key_versions,
    )
    return encrypt_ticket(payload, signatures)


def authenticate_with_service(ticket_blob: dict, service_port: int = SERVICE_PORTS[DEFAULT_SERVICE_ID]) -> dict:
    return send_json_request(HOST, service_port, {"action": "authenticate", "ticket": ticket_blob})


def run_benchmark(client_id: str, service_id: str, service_port: int, rounds: int) -> None:
    print(f"[Benchmark] Starting benchmark for client={client_id}, service={service_id}, rounds={rounds}")

    as_public, as_versions = fetch_authority_info(AS_PORTS)
    tgs_public, tgs_versions = fetch_authority_info(TGS_PORTS)

    tgt_times = []
    st_times = []
    auth_times = []

    for _ in range(rounds):
        t0 = time.perf_counter()
        _tgt = request_tgt(client_id, AS_PORTS, as_public, as_versions)
        t1 = time.perf_counter()

        st = request_service_ticket(client_id, TGS_PORTS, tgs_public, tgs_versions, service_id)
        t2 = time.perf_counter()

        resp = authenticate_with_service(st, service_port=service_port)
        t3 = time.perf_counter()
        if not resp.get("ok"):
            raise RuntimeError(f"Benchmark auth failed: {resp}")

        tgt_times.append((t1 - t0) * 1000.0)
        st_times.append((t2 - t1) * 1000.0)
        auth_times.append((t3 - t2) * 1000.0)

    def stats_line(label: str, values: list[float]) -> str:
        return (
            f"- {label}: mean={statistics.mean(values):.3f} ms, "
            f"median={statistics.median(values):.3f} ms, "
            f"min={min(values):.3f} ms, max={max(values):.3f} ms"
        )

    print("\nBenchmark Results")
    print(stats_line("Distributed AS phase (TGT)", tgt_times))
    print(stats_line("Distributed TGS phase (Service Ticket)", st_times))
    print(stats_line("Service authentication phase", auth_times))


def main() -> None:
    parser = argparse.ArgumentParser(description="Run client flow")
    parser.add_argument("--client-id", default="clientA")
    parser.add_argument("--service-id", default=DEFAULT_SERVICE_ID)
    parser.add_argument("--service-port", type=int)
    parser.add_argument("--benchmark-rounds", type=int, default=0)
    args = parser.parse_args()

    service_port = args.service_port if args.service_port is not None else SERVICE_PORTS.get(args.service_id, SERVICE_PORTS[DEFAULT_SERVICE_ID])

    if args.benchmark_rounds > 0:
        run_benchmark(args.client_id, args.service_id, service_port, args.benchmark_rounds)
        return

    print("[Client] Fetching AS public info...")
    as_public, as_versions = fetch_authority_info(AS_PORTS)
    print(f"[Client] AS key versions loaded for {len(as_versions)} authorities.")

    print("[Client] Fetching TGS public info...")
    tgs_public, tgs_versions = fetch_authority_info(TGS_PORTS)
    print(f"[Client] TGS key versions loaded for {len(tgs_versions)} authorities.")

    print("[Client] Requesting TGT with 2-of-3 AS signatures...")
    tgt = request_tgt(args.client_id, AS_PORTS, as_public, as_versions)
    tgt_sig_count = len(decrypt_ticket(tgt).get("signatures", []))
    print(f"[Client] TGT issued successfully. Signatures collected: {tgt_sig_count}")

    print("[Client] Requesting Service Ticket with 2-of-3 TGS signatures...")
    st = request_service_ticket(args.client_id, TGS_PORTS, tgs_public, tgs_versions, args.service_id)
    st_sig_count = len(decrypt_ticket(st).get("signatures", []))
    print(f"[Client] Service Ticket issued successfully. Signatures collected: {st_sig_count}")

    print("[Client] Authenticating with service server...")
    auth = authenticate_with_service(st, service_port=service_port)

    if auth.get("ok"):
        print("[Client] Authentication SUCCESS: Ticket valid")
    else:
        print(f"[Client] Authentication FAILED: {auth.get('error', 'Unknown error')}")

    print("\nSummary")
    print(f"- TGT signatures: {tgt_sig_count}")
    print(f"- Service Ticket signatures: {st_sig_count}")
    print(f"- Final service auth: {'SUCCESS' if auth.get('ok') else 'FAILED'}")


if __name__ == "__main__":
    main()
