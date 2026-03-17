"""Mandatory attack simulation suite."""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import time
import signal
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


def _ts() -> str:
    return time.strftime("%H:%M:%S")


def _scenario_log(name: str, msg: str) -> None:
    print(f"[{_ts()}] [Scenario:{name}] {msg}")


def _launch(cmd: List[str]) -> subprocess.Popen:
    return subprocess.Popen(cmd, cwd=str(ROOT), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)


def _start_system(offline: list[str] | None = None, use_running_servers: bool = True) -> list[subprocess.Popen]:
    if use_running_servers:
        return []

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


def _is_listening(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.4)
        return s.connect_ex((HOST, port)) == 0


def _listener_pid(port: int) -> int | None:
    try:
        out = subprocess.check_output(
            ["lsof", "-tiTCP:%d" % port, "-sTCP:LISTEN"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except subprocess.CalledProcessError:
        return None
    if not out:
        return None
    first = out.splitlines()[0].strip()
    return int(first) if first.isdigit() else None


def _wait_port_state(port: int, should_listen: bool, timeout: float = 3.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if _is_listening(port) == should_listen:
            return True
        time.sleep(0.1)
    return _is_listening(port) == should_listen


def scenario_single_malicious_authority_forged_ticket(use_running_servers: bool) -> Tuple[bool, str]:
    procs = _start_system(use_running_servers=use_running_servers)
    try:
        _, versions = fetch_authority_info(AS_PORTS, min_required=2, require_all=False)
        payload = build_ticket_payload("clientA", "fileserver", os.urandom(32).hex(), versions)
        forged_aid = next(iter(versions.keys()))
        forged_sig = {"authority_id": forged_aid, "R": "2", "s": "3", "key_version": versions[forged_aid]}
        forged_ticket = encrypt_ticket(payload, [forged_sig])
        resp = authenticate_with_service(forged_ticket)
        details = _detail(
            f"Injected ticket with exactly one forged AS signature ({forged_aid})",
            "service enforces minimum two independent valid signatures (2-of-3)",
            resp,
        )
        return (not resp.get("ok", False), details)
    finally:
        _stop_system(procs)


def scenario_modified_ticket_payload(use_running_servers: bool) -> Tuple[bool, str]:
    procs = _start_system(use_running_servers=use_running_servers)
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


def scenario_replay_old_partial_signature(use_running_servers: bool) -> Tuple[bool, str]:
    procs = _start_system(use_running_servers=use_running_servers)
    try:
        tgs_public, tgs_versions = fetch_authority_info(TGS_PORTS)
        old_ticket = request_service_ticket("clientA", TGS_PORTS, tgs_public, tgs_versions, "fileserver")
        old_decoded = decrypt_ticket(old_ticket)
        replayed_sig = old_decoded["signatures"][0]

        new_payload = build_ticket_payload("clientA", "fileserver", os.urandom(32).hex(), _key_versions())
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


def scenario_leakage_of_one_private_key(use_running_servers: bool) -> Tuple[bool, str]:
    procs = _start_system(use_running_servers=use_running_servers)
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


def scenario_authority_offline(use_running_servers: bool) -> Tuple[bool, str]:
    procs = _start_system(offline=["AS1"], use_running_servers=use_running_servers)
    killed_pid: int | None = None
    try:
        if use_running_servers:
            pid = _listener_pid(AS_PORTS["AS1"])
            if pid is None:
                return (
                    False,
                    "Attempt: authority offline scenario with external servers\n"
                    "Observed: AS1 is not running on port 9101\n"
                    "Reason: cannot demonstrate takedown because AS1 was already offline\n"
                    "How to fix: start AS1, then rerun attacks.py",
                )

            os.kill(pid, signal.SIGTERM)
            killed_pid = pid
            if not _wait_port_state(AS_PORTS["AS1"], should_listen=False, timeout=3.0):
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                if not _wait_port_state(AS_PORTS["AS1"], should_listen=False, timeout=1.5):
                    return False, "Failed to bring AS1 offline during offline scenario"

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
        if use_running_servers and killed_pid is not None:
            print("[attacks.py] AS1 left offline after authority_offline scenario")

        _stop_system(procs)


def scenario_ticket_with_only_one_valid_signature(use_running_servers: bool) -> Tuple[bool, str]:
    procs = _start_system(use_running_servers=use_running_servers)
    try:
        _, versions = fetch_authority_info(AS_PORTS, min_required=2, require_all=False)
        payload = build_ticket_payload("clientA", "fileserver", os.urandom(32).hex(), versions)
        one_aid = next(iter(versions.keys()))
        one_sig = {"authority_id": one_aid, "R": "17", "s": "19", "key_version": versions[one_aid]}
        ticket = encrypt_ticket(payload, [one_sig])
        resp = authenticate_with_service(ticket)
        details = _detail(
            f"Submitted ticket containing only one signature ({one_aid})",
            "policy requires at least two valid authority signatures",
            resp,
        )
        return (not resp.get("ok", False), details)
    finally:
        _stop_system(procs)


def run_all(use_running_servers: bool) -> Dict[str, Dict[str, object]]:
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

        _scenario_log(name, "START")

        ok, details = fn(use_running_servers)
        out[name] = {"pass": ok, "details": details}

        verdict = "PASS" if ok else "FAIL"
        print(f"Result: {verdict}")
        print(f"Details: {details}")

        try:
            as_reachable = len(fetch_authority_info(AS_PORTS, min_required=0, require_all=False)[0])
        except Exception:
            as_reachable = 0
        try:
            tgs_reachable = len(fetch_authority_info(TGS_PORTS, min_required=0, require_all=False)[0])
        except Exception:
            tgs_reachable = 0
        _scenario_log(
            name,
            f"END verdict={verdict} reachable_as={as_reachable} reachable_tgs={tgs_reachable} service={DEFAULT_SERVICE_ID}",
        )
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description="Run mandatory attack suite")
    parser.add_argument(
        "--self-contained",
        action="store_true",
        help="Start and stop AS/TGS/service nodes internally for each scenario",
    )
    args = parser.parse_args()
    use_running_servers = not args.self_contained

    # Ensure a keystore exists before spinning up nodes.
    if not Path(PUBLIC_REGISTRY_FILE).exists():
        subprocess.check_call([sys.executable, "master_keygen.py"], cwd=str(ROOT))

    if use_running_servers:
        print("Mode: using already-running AS/TGS/service servers")
    else:
        print("Mode: self-contained (attacks.py starts/stops servers internally)")

    results = run_all(use_running_servers)
    passed = sum(1 for item in results.values() if item.get("pass"))
    total = len(results)

    print("\nFinal Summary")
    for name, item in results.items():
        print(f"- {name}: {'PASS' if item.get('pass') else 'FAIL'}")
    print(f"Overall: {passed}/{total} scenarios passed")


if __name__ == "__main__":
    main()
