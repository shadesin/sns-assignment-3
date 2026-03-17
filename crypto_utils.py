"""Common constants and crypto helpers used by all deliverable scripts."""

from __future__ import annotations

import hashlib
import json
import random
from pathlib import Path
from typing import Dict

import fcntl

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# 2048-bit MODP prime (RFC 3526 group 14)
P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF",
    16,
)
Q = (P - 1) // 2
G = 4

HOST = "127.0.0.1"
AS_PORTS = {"AS1": 9101, "AS2": 9102, "AS3": 9103}
TGS_PORTS = {"TGS1": 9201, "TGS2": 9202, "TGS3": 9203}
SERVICE_PORTS = {"fileserver": 9301, "mailserver": 9302}
DEFAULT_SERVICE_ID = "fileserver"
SERVICE_PORT = SERVICE_PORTS[DEFAULT_SERVICE_ID]
AUTHORITY_IDS = ["AS1", "AS2", "AS3", "TGS1", "TGS2", "TGS3"]

DEFAULT_LIFETIME_SECONDS = 300
ROOT_DIR = Path(__file__).resolve().parent
KEYS_DIR = ROOT_DIR / "keys"
PUBLIC_REGISTRY_FILE = ROOT_DIR / "authority_public_keys.json"

TICKET_ENC_KEY = bytes.fromhex(
    "7b49ee4f5463dbcb2ce4f9d41e08f65e3a1932cfe8fd263d46de197f7ddaa023"
)
CLIENT_LONG_TERM_KEYS = {
    "clientA": bytes.fromhex(
        "4d96a44ce5be0ef653f8c7d1c14cc6a4593ee4a4a5d8d4efef0a2eb18cd9f6ba"
    ),
    "clientB": bytes.fromhex(
        "6f115f823d203f9006008698a77be9d7f4c328cf9a2f2df2eb18e8a6bc2c1471"
    ),
    "clientC": bytes.fromhex(
        "2fe7ea95f164f6f6f43f6c845393ce37c8e26a23cd5ef6f8d3bf5cbca6ccfa8d"
    ),
}


def mod_exp(base: int, exponent: int, modulus: int) -> int:
    result = 1
    base = base % modulus
    exp = exponent
    while exp > 0:
        if exp & 1:
            result = (result * base) % modulus
        base = (base * base) % modulus
        exp >>= 1
    return result


def hash_to_q(message_bytes: bytes, q: int) -> int:
    digest = hashlib.sha256(message_bytes).digest()
    return int.from_bytes(digest, "big") % q


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("Invalid PKCS#7 input length")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Invalid PKCS#7 padding length")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Invalid PKCS#7 padding bytes")
    return data[:-pad_len]


def aes256_cbc_encrypt(key: bytes, plaintext: bytes) -> Dict[str, str]:
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pkcs7_pad(plaintext, 16))
    return {"iv": iv.hex(), "ciphertext": ciphertext.hex()}


def aes256_cbc_decrypt(key: bytes, iv_hex: str, ciphertext_hex: str) -> bytes:
    iv = bytes.fromhex(iv_hex)
    ciphertext = bytes.fromhex(ciphertext_hex)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = cipher.decrypt(ciphertext)
    return pkcs7_unpad(padded, 16)


def canonical_payload_bytes(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def schnorr_keygen(p: int, q: int, g: int, rng_int) -> Dict[str, int]:
    x = rng_int(1, q - 1)
    y = mod_exp(g, x, p)
    return {"x": x, "y": y}


def schnorr_sign(payload: dict, authority_id: str, x: int) -> Dict[str, str]:
    rng = random.SystemRandom()
    k = rng.randint(1, Q - 1)
    r = mod_exp(G, k, P)
    msg = canonical_payload_bytes(payload)
    e = hash_to_q(msg + str(r).encode("utf-8") + authority_id.encode("utf-8"), Q)
    s = (k + (e * x)) % Q
    return {"authority_id": authority_id, "R": str(r), "s": str(s)}


def schnorr_verify(payload: dict, signature: dict, y: int) -> bool:
    try:
        authority_id = signature["authority_id"]
        r = int(signature["R"])
        s = int(signature["s"])
    except (KeyError, ValueError, TypeError):
        return False

    if r <= 0 or r >= P or s < 0 or s >= Q:
        return False

    msg = canonical_payload_bytes(payload)
    e = hash_to_q(msg + str(r).encode("utf-8") + authority_id.encode("utf-8"), Q)
    left = mod_exp(G, s, P)
    right = (r * mod_exp(y, e, P)) % P
    return left == right


def load_keystore(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def load_public_registry() -> dict:
    if not PUBLIC_REGISTRY_FILE.exists():
        return {"public_keys": {}, "key_versions": {}}
    with open(PUBLIC_REGISTRY_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)
    return {
        "public_keys": data.get("public_keys", {}),
        "key_versions": data.get("key_versions", {}),
    }


def update_public_registry(authority_id: str, public_key: int, key_version: int) -> None:
    PUBLIC_REGISTRY_FILE.parent.mkdir(parents=True, exist_ok=True)
    if not PUBLIC_REGISTRY_FILE.exists():
        _write_json(PUBLIC_REGISTRY_FILE, {"public_keys": {}, "key_versions": {}})

    with open(PUBLIC_REGISTRY_FILE, "r+", encoding="utf-8") as f:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        try:
            raw = f.read().strip()
            data = json.loads(raw) if raw else {"public_keys": {}, "key_versions": {}}
            data.setdefault("public_keys", {})
            data.setdefault("key_versions", {})
            data["public_keys"][authority_id] = str(public_key)
            data["key_versions"][authority_id] = int(key_version)

            f.seek(0)
            json.dump(data, f, indent=2)
            f.truncate()
        finally:
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)


def get_authority_private_key_path(authority_id: str) -> Path:
    return KEYS_DIR / f"{authority_id}_private.json"


def load_or_create_authority_key(authority_id: str) -> dict:
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    key_file = get_authority_private_key_path(authority_id)

    if key_file.exists():
        with open(key_file, "r", encoding="utf-8") as f:
            rec = json.load(f)
        rec["private_key"] = int(rec["private_key"])
        rec["public_key"] = int(rec["public_key"])
        rec["key_version"] = int(rec.get("key_version", 1))
        update_public_registry(authority_id, rec["public_key"], rec["key_version"])
        return rec

    kp = schnorr_keygen(P, Q, G, random.SystemRandom().randint)
    rec = {
        "authority_id": authority_id,
        "private_key": kp["x"],
        "public_key": kp["y"],
        "key_version": 1,
    }
    _write_json(
        key_file,
        {
            "authority_id": authority_id,
            "private_key": str(rec["private_key"]),
            "public_key": str(rec["public_key"]),
            "key_version": rec["key_version"],
        },
    )
    update_public_registry(authority_id, rec["public_key"], rec["key_version"])
    return rec


def build_ticket_payload(client_id: str, service_id: str, session_key_hex: str, key_versions: dict) -> dict:
    import time

    return {
        "client_id": client_id,
        "service_id": service_id,
        "issue_ts": int(time.time()),
        "lifetime": DEFAULT_LIFETIME_SECONDS,
        "session_key": session_key_hex,
        "authority_metadata": {"min_valid_signatures": 2, "scheme": "Schnorr"},
        "key_version": key_versions,
    }


def encrypt_ticket(payload: dict, signatures: list[dict]) -> dict:
    ticket_obj = {"payload": payload, "signatures": signatures}
    encrypted = aes256_cbc_encrypt(TICKET_ENC_KEY, canonical_payload_bytes(ticket_obj))
    return {"encrypted": encrypted}


def decrypt_ticket(ticket_blob: dict) -> dict:
    encrypted = ticket_blob["encrypted"]
    raw = aes256_cbc_decrypt(TICKET_ENC_KEY, encrypted["iv"], encrypted["ciphertext"])
    return json.loads(raw.decode("utf-8"))


def verify_ticket(ticket_blob: dict, public_keys: dict[str, int], expected_versions: dict[str, int]) -> tuple[bool, str]:
    import time

    try:
        ticket_obj = decrypt_ticket(ticket_blob)
    except Exception as exc:  # pylint: disable=broad-except
        return False, f"AES/PKCS7 validation failed: {exc}"

    payload = ticket_obj.get("payload")
    signatures = ticket_obj.get("signatures", [])

    if not isinstance(payload, dict):
        return False, "Ticket payload missing"

    required = [
        "client_id",
        "service_id",
        "issue_ts",
        "lifetime",
        "session_key",
        "authority_metadata",
        "key_version",
    ]
    for field in required:
        if field not in payload:
            return False, f"Ticket field missing: {field}"

    now = int(time.time())
    if now > int(payload["issue_ts"]) + int(payload["lifetime"]):
        return False, "Ticket expired"

    key_versions = payload.get("key_version", {})
    valid = set()
    for sig in signatures:
        aid = sig.get("authority_id")
        if aid not in public_keys:
            continue
        if key_versions.get(aid) != expected_versions.get(aid):
            continue
        if schnorr_verify(payload, sig, public_keys[aid]):
            valid.add(aid)

    if len(valid) < 2:
        return False, "Ticket does not contain at least two valid signatures"

    return True, "Ticket valid"


def verify_ticket_for_service(
    ticket_blob: dict,
    public_keys: dict[str, int],
    expected_versions: dict[str, int],
    expected_service_id: str,
) -> tuple[bool, str]:
    ok, msg = verify_ticket(ticket_blob, public_keys, expected_versions)
    if not ok:
        return ok, msg
    payload = decrypt_ticket(ticket_blob)["payload"]
    if payload.get("service_id") != expected_service_id:
        return False, "Ticket service ID mismatch"
    return True, "Ticket valid"
