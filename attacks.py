"""Mandatory attack simulation suite."""

from __future__ import annotations

import json
import random
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Tuple

from client import authenticate_with_service, fetch_authority_info, request_service_ticket, request_tgt
from crypto_utils import AS_PORTS, DEFAULT_SERVICE_ID, HOST, PUBLIC_REGISTRY_FILE, SERVICE_PORTS, TGS_PORTS, build_ticket_payload, decrypt_ticket, encrypt_ticket

ROOT = Path(__file__).resolve().parent


def _format_response_details(resp: dict) -> str:
    if resp.get("ok"):
        return f"Service accepted ticket. Message: {resp.get('message', 'No message')}"
    return f"Service rejected ticket. Reason: {resp.get('error', 'Unknown error')}"


def _detail(attempt: str, expected_defense: str, resp: dict) -> str:
    observed = "Service accepted ticket" if resp.get("ok") else "Service rejected ticket"
    reason = resp.get("message", "No message") if resp.get("ok") else resp.get("error", "Unknown error")
    return (
        f"Attempt: {attempt}\n"
        f"Observed: {observed}\n"
        f"Reason: {reason}\n"
        f"Why blocked: {expected_defense}"
    )


def _launch(cmd: List[str]) -> subprocess.Popen:
    return subprocess.Popen(cmd, cwd=str(ROOT), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)


def _start_system(offline: list[str] | None = None) -> list[subprocess.Popen]:
    offline_set = set(offline or [])
    procs: list[subprocess.Popen] = []
    for aid, port in AS_PORTS.items():
        if aid in offline_set:
            continue
        procs.append(_launch([sys.executable, "as_node.py", "--id", aid, "--host", HOST, "--port", str(port)]))
    for aid, port in TGS_PORTS.items():
        if aid in offline_set:
            continue
        procs.append(_launch([sys.executable, "tgs_node.py", "--id", aid, "--host", HOST, "--port", str(port)]))
    procs.append(
        _launch(
            [
                sys.executable,
                "service_server.py",
                "--service-id",
                DEFAULT_SERVICE_ID,
                "--host",
                HOST,
                "--port",
                str(SERVICE_PORTS[DEFAULT_SERVICE_ID]),
            ]
        )
    )
    time.sleep(1.0)
    return procs


def _stop_system(procs: list[subprocess.Popen]) -> None:
    for p in procs:
        if p.poll() is None:
            p.terminate()
    for p in procs:
        if p.poll() is None:
            p.wait(timeout=2)


def _key_versions() -> dict[str, int]:
    with open(PUBLIC_REGISTRY_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)
    return {k: int(v) for k, v in data["key_versions"].items()}


def scenario_single_malicious_authority_forged_ticket() -> Tuple[bool, str]:
    procs = _start_system()
    try:
        _, versions = fetch_authority_info(AS_PORTS)
        payload = build_ticket_payload("clientA", "fileserver", random.randbytes(32).hex(), versions)
        forged_sig = {"authority_id": "AS1", "R": "2", "s": "3", "key_version": versions["AS1"]}
        forged_ticket = encrypt_ticket(payload, [forged_sig])
        resp = authenticate_with_service(forged_ticket)
        details = _detail(
            "Injected ticket with exactly one forged AS signature",
            "service enforces minimum two independent valid signatures (2-of-3)",
            resp,
        )
        return (not resp.get("ok", False), details)
    finally:
        _stop_system(procs)


def scenario_modified_ticket_payload() -> Tuple[bool, str]:
    procs = _start_system()
    try:
        tgs_public, tgs_versions = fetch_authority_info(TGS_PORTS)
        ticket = request_service_ticket("clientA", TGS_PORTS, tgs_public, tgs_versions, "fileserver")
        decoded = decrypt_ticket(ticket)
        decoded["payload"]["service_id"] = "evilservice"
        tampered = encrypt_ticket(decoded["payload"], decoded["signatures"])
        resp = authenticate_with_service(tampered)
        details = _detail(
            "Modified signed payload field service_id from fileserver to evilservice",
            "Schnorr challenge binds signature to payload; tampering invalidates signatures and/or service-id check",
            resp,
        )
        return (not resp.get("ok", False), details)
    finally:
        _stop_system(procs)


def scenario_replay_old_partial_signature() -> Tuple[bool, str]:
    procs = _start_system()
    try:
        tgs_public, tgs_versions = fetch_authority_info(TGS_PORTS)
        old_ticket = request_service_ticket("clientA", TGS_PORTS, tgs_public, tgs_versions, "fileserver")
        old_decoded = decrypt_ticket(old_ticket)
        replayed_sig = old_decoded["signatures"][0]

        new_payload = build_ticket_payload("clientA", "fileserver", random.randbytes(32).hex(), _key_versions())
        fake_sig = {"authority_id": "TGS3", "R": "7", "s": "11", "key_version": 1}
        replay_ticket = encrypt_ticket(new_payload, [replayed_sig, fake_sig])
        resp = authenticate_with_service(replay_ticket)
        details = _detail(
            "Reused an old valid partial signature on a different payload",
            "signature verifies only for its original message; replayed share fails on new payload",
            resp,
        )
        return (not resp.get("ok", False), details)
    finally:
        _stop_system(procs)


def scenario_leakage_of_one_private_key() -> Tuple[bool, str]:
    procs = _start_system()
    try:
        tgs_public, tgs_versions = fetch_authority_info(TGS_PORTS)
        legit = request_service_ticket("clientA", TGS_PORTS, tgs_public, tgs_versions, "fileserver")
        decoded = decrypt_ticket(legit)
        one_real = decoded["signatures"][0]
        forged_second = {"authority_id": "TGS2", "R": "13", "s": "29", "key_version": 1}
        ticket = encrypt_ticket(decoded["payload"], [one_real, forged_second])
        resp = authenticate_with_service(ticket)
        details = _detail(
            "Used one genuine share (simulating one leaked key) plus one forged share",
            "single-key leakage is contained because second independent valid signature is still required",
            resp,
        )
        return (not resp.get("ok", False), details)
    finally:
        _stop_system(procs)


def scenario_authority_offline() -> Tuple[bool, str]:
    procs = _start_system(offline=["AS1"])
    try:
        active_as = {k: v for k, v in AS_PORTS.items() if k != "AS1"}
        as_public, as_versions = fetch_authority_info(active_as)
        _tgt = request_tgt("clientA", active_as, as_public, as_versions)

        tgs_public, tgs_versions = fetch_authority_info(TGS_PORTS)
        ticket = request_service_ticket("clientA", TGS_PORTS, tgs_public, tgs_versions, DEFAULT_SERVICE_ID)
        resp = authenticate_with_service(ticket, service_port=SERVICE_PORTS[DEFAULT_SERVICE_ID])
        if resp.get("ok"):
            return (
                True,
                "Attempt: kept one authority (AS1) offline\n"
                "Observed: Service accepted ticket\n"
                "Reason: Ticket valid\n"
                "Why allowed: remaining two AS authorities are sufficient for 2-of-3 threshold",
            )
        return False, _format_response_details(resp)
    finally:
        _stop_system(procs)


def scenario_ticket_with_only_one_valid_signature() -> Tuple[bool, str]:
    procs = _start_system()
    try:
        _, versions = fetch_authority_info(AS_PORTS)
        payload = build_ticket_payload("clientA", "fileserver", random.randbytes(32).hex(), versions)
        one_sig = {"authority_id": "AS1", "R": "17", "s": "19", "key_version": versions["AS1"]}
        ticket = encrypt_ticket(payload, [one_sig])
        resp = authenticate_with_service(ticket)
        details = _detail(
            "Submitted ticket containing only one signature",
            "policy requires at least two valid authority signatures",
            resp,
        )
        return (not resp.get("ok", False), details)
    finally:
        _stop_system(procs)


def run_all() -> Dict[str, Dict[str, object]]:
    scenarios = {
        "single_malicious_authority_forged_ticket": scenario_single_malicious_authority_forged_ticket,
        "modified_ticket_payload": scenario_modified_ticket_payload,
        "replay_old_partial_signature": scenario_replay_old_partial_signature,
        "leakage_of_one_private_signing_key": scenario_leakage_of_one_private_key,
        "authority_offline": scenario_authority_offline,
        "ticket_with_only_one_valid_signature": scenario_ticket_with_only_one_valid_signature,
    }
    descriptions = {
        "single_malicious_authority_forged_ticket": "Single malicious authority tries to forge ticket",
        "modified_ticket_payload": "Attacker modifies ticket payload after signing",
        "replay_old_partial_signature": "Replay old partial signature on new payload",
        "leakage_of_one_private_signing_key": "One authority private key leakage",
        "authority_offline": "Authority offline scenario",
        "ticket_with_only_one_valid_signature": "Ticket containing only one valid signature",
    }

    out = {}
    print("Attack Suite: Kerberos Under Partial Compromise")
    print("Expected: attacks should be blocked, and offline-authority case should still operate")

    for name, fn in scenarios.items():
        try:
            print(f"\nAttack: {descriptions.get(name, name)}")
            input("Press Enter to run this attack...")
        except EOFError:
            # Non-interactive mode fallback.
            pass

        ok, details = fn()
        out[name] = {"pass": ok, "details": details}

        verdict = "PASS" if ok else "FAIL"
        print(f"Result: {verdict}")
        print(f"Details: {details}")
    return out


def main() -> None:
    # Ensure a keystore exists before spinning up nodes.
    if not Path(PUBLIC_REGISTRY_FILE).exists():
        subprocess.check_call([sys.executable, "master_keygen.py"], cwd=str(ROOT))

    results = run_all()
    passed = sum(1 for item in results.values() if item.get("pass"))
    total = len(results)

    print("\nFinal Summary")
    for name, item in results.items():
        print(f"- {name}: {'PASS' if item.get('pass') else 'FAIL'}")
    print(f"Overall: {passed}/{total} scenarios passed")


if __name__ == "__main__":
    main()
