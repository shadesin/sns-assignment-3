# SNS Lab Assignment 3
## Kerberos Under Partial Compromise using Schnorr Multi-Signatures

### Team Details
- Team Number: 5
- Souradeep Das (Roll: 2025201004)
- Kushal Mukherjee (Roll: 2025201072)
- Srinjoy Sengupta (Roll: 2025202010)

## Deliverables
- `master_keygen.py`
- `as_node.py`
- `tgs_node.py`
- `service_server.py`
- `client.py`
- `crypto_utils.py`
- `attacks.py`
- `README.md`
- `SECURITY.md`

## Implementation Summary
This project implements a Kerberos-inspired authentication system with distributed trust:
- 3 AS authorities (`AS1`, `AS2`, `AS3`)
- 3 TGS authorities (`TGS1`, `TGS2`, `TGS3`)
- threshold policy requiring at least 2 valid Schnorr signatures
- AES-256-CBC encrypted tickets with manual PKCS#7 padding
- attack simulations to demonstrate compromise containment

## What Each File Does
- `master_keygen.py`: initializes key directories and public key registry.
- `as_node.py`: AS authority server process, signs TGT payload shares.
- `tgs_node.py`: TGS authority server process, signs service-ticket payload shares.
- `service_server.py`: validates decrypted ticket, key version, service ID, and 2-of-3 signatures.
- `client.py`: runs protocol flow and supports benchmark mode.
- `crypto_utils.py`: cryptographic primitives and ticket encode/decode/verification helpers.
- `attacks.py`: mandatory attack scenario runner.
- `SECURITY.md`: detailed threat, security reasoning, and risk analysis.

## Setup
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install pycryptodome
```

Supported demo clients:
- `clientA`
- `clientB`
- `clientC`

Supported demo services:
- `fileserver`
- `mailserver`

## Run Order
1. Generate key material:
```bash
python master_keygen.py
```

This creates:
- `authority_public_keys.json` (public keys and key versions)
- `keys/` directory for per-authority private key files

Important key model:
- each authority generates and stores only its own private key on first startup
- private keys are not stored in a single shared private-key file

2. Start authorities and service servers (separate terminals):
```bash
python as_node.py --id AS1
python as_node.py --id AS2
python as_node.py --id AS3
python tgs_node.py --id TGS1
python tgs_node.py --id TGS2
python tgs_node.py --id TGS3
python service_server.py --service-id fileserver
python service_server.py --service-id mailserver
```

3. Run clients:
```bash
python client.py --client-id clientA --service-id fileserver
python client.py --client-id clientB --service-id fileserver
python client.py --client-id clientC --service-id mailserver
```

4. Run mandatory attack suite:
```bash
python attacks.py
```

## Mandatory Attack Coverage
`attacks.py` includes all assignment-required scenarios:
- single malicious authority issuing forged ticket
- modified ticket payload
- replay of old partial signature
- leakage of one authority private key
- authority offline scenario
- ticket containing only one valid signature

## Performance Benchmarking (Extensive)

### Methodology
- Environment: local machine, localhost TCP, Python virtual environment.
- Authorities running: AS1-3, TGS1-3.
- Services running: `fileserver` and `mailserver`.
- Clients benchmarked: `clientA`, `clientB`, `clientC`.
- Rounds per benchmark case: 30.
- Metrics captured per phase:
  - Distributed AS phase (TGT issuance)
  - Distributed TGS phase (service-ticket issuance)
  - Service authentication phase
- Statistic set: mean, median, min, max latency in milliseconds.

Benchmark command template:
```bash
python client.py --benchmark-rounds 30 --client-id <client> --service-id <service>
```

### Raw Benchmark Results

| Client | Service | AS Phase Mean (ms) | AS Median | AS Min | AS Max | TGS Phase Mean (ms) | TGS Median | TGS Min | TGS Max | Service Auth Mean (ms) | Auth Median | Auth Min | Auth Max |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| clientA | fileserver | 3.348 | 3.215 | 3.103 | 6.360 | 3.209 | 3.168 | 3.041 | 3.768 | 3.985 | 3.978 | 3.744 | 4.858 |
| clientA | mailserver | 3.293 | 3.272 | 3.146 | 3.921 | 3.219 | 3.215 | 3.078 | 3.466 | 4.069 | 4.029 | 3.845 | 4.906 |
| clientB | fileserver | 3.307 | 3.285 | 3.174 | 3.729 | 3.197 | 3.193 | 3.081 | 3.389 | 4.043 | 4.026 | 3.885 | 4.271 |
| clientB | mailserver | 3.295 | 3.269 | 3.084 | 4.122 | 3.201 | 3.191 | 3.006 | 3.361 | 4.028 | 4.021 | 3.869 | 4.331 |
| clientC | fileserver | 3.491 | 3.255 | 3.149 | 7.598 | 3.606 | 3.235 | 3.041 | 8.322 | 4.548 | 4.050 | 3.836 | 10.326 |
| clientC | mailserver | 3.325 | 3.278 | 3.152 | 4.259 | 3.220 | 3.200 | 3.080 | 3.419 | 4.077 | 4.079 | 3.872 | 4.305 |

### Aggregated Averages Across All 6 Cases
- AS phase mean latency average: 3.343 ms
- TGS phase mean latency average: 3.275 ms
- Service authentication mean latency average: 4.125 ms

### Interpretation
- Typical latency is stable in low single-digit milliseconds for all three phases.
- Service-auth phase is consistently the most expensive, due to decryption + multi-signature verification.
- Outliers (e.g., clientC/fileserver max values) indicate occasional scheduling/network jitter on localhost.
- Multi-authority overhead remains modest while providing compromise tolerance and authority-offline resilience.

### Reproducibility Notes
- Run benchmarks only after all AS/TGS/service processes are started.
- Ensure no stale processes are holding required ports.
- Use identical rounds and same local conditions to compare runs fairly.
