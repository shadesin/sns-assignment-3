"""Generate independent Schnorr key pairs for AS/TGS authorities."""

from __future__ import annotations

import json

from crypto_utils import AUTHORITY_IDS, KEYS_DIR, PUBLIC_REGISTRY_FILE


def initialize_key_material() -> None:
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    if not PUBLIC_REGISTRY_FILE.exists():
        with open(PUBLIC_REGISTRY_FILE, "w", encoding="utf-8") as f:
            json.dump({"public_keys": {}, "key_versions": {}}, f, indent=2)


def main() -> None:
    initialize_key_material()
    print("Master key initialization complete")
    print(f"- Public registry file: {PUBLIC_REGISTRY_FILE}")
    print(f"- Private key directory: {KEYS_DIR}")
    print("- Each authority generates and stores its own private key on first startup")
    print(f"- Authorities: {', '.join(AUTHORITY_IDS)}")


if __name__ == "__main__":
    main()
