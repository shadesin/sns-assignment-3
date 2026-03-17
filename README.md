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

Optional cleanup before starting nodes (recommended if you see "Address already in use"):
```bash
lsof -tiTCP:9101,9102,9103,9201,9202,9203,9301,9302 -sTCP:LISTEN | tr '\n' ' ' | xargs -r kill -9
```

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

Client resilience note:
- client flow tolerates one unavailable AS and one unavailable TGS (it proceeds as long as at least 2 authorities in that phase are reachable)
- if fewer than 2 authorities are reachable in a phase, client exits with a clear error

4. Run mandatory attack suite:
```bash
python attacks.py
```

By default, `attacks.py` uses the AS/TGS/service servers you already started, so attack traffic appears in those server terminals.

In this default mode, the "authority offline" scenario takes AS1 down and leaves it offline after that scenario, so subsequent client runs observe reduced AS availability.

Optional self-contained mode (for quick standalone testing):
```bash
python attacks.py --self-contained
```

## Mandatory Attack Coverage
`attacks.py` includes all assignment-required scenarios:
- single malicious authority issuing forged ticket
- modified ticket payload
- replay of old partial signature
- leakage of one authority private key
- authority offline scenario
- ticket containing only one valid signature

## Performance Benchmarking

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
| clientA | fileserver | 7.122 | 6.984 | 6.828 | 10.591 | 6.993 | 6.989 | 6.768 | 7.367 | 4.084 | 4.034 | 3.886 | 4.841 |
| clientA | mailserver | 7.019 | 6.981 | 6.807 | 7.716 | 6.968 | 6.975 | 6.770 | 7.128 | 4.094 | 4.081 | 3.915 | 4.832 |
| clientB | fileserver | 6.961 | 6.924 | 6.731 | 7.709 | 6.882 | 6.875 | 6.690 | 7.054 | 4.052 | 4.054 | 3.889 | 4.236 |
| clientB | mailserver | 6.950 | 6.926 | 6.784 | 7.509 | 6.868 | 6.868 | 6.696 | 7.122 | 3.987 | 3.986 | 3.871 | 4.103 |
| clientC | fileserver | 6.903 | 6.873 | 6.700 | 7.594 | 6.860 | 6.837 | 6.712 | 7.072 | 4.033 | 4.019 | 3.922 | 4.208 |
| clientC | mailserver | 6.943 | 6.930 | 6.633 | 7.641 | 6.890 | 6.893 | 6.727 | 7.007 | 3.999 | 3.989 | 3.876 | 4.247 |

### Aggregated Averages Across All 6 Cases
- AS phase mean latency average: 6.983 ms
- TGS phase mean latency average: 6.910 ms
- Service authentication mean latency average: 4.042 ms

### Interpretation
- Typical latency is stable in low single-digit milliseconds for all three phases.
- Service-auth phase is consistently the most expensive, due to decryption + multi-signature verification.
- Outliers (e.g., clientC/fileserver max values) indicate occasional scheduling/network jitter on localhost.
- Multi-authority overhead remains modest while providing compromise tolerance and authority-offline resilience.

### Reproducibility Notes
- Run benchmarks only after all AS/TGS/service processes are started.
- Ensure no stale processes are holding required ports.
- Use identical rounds and same local conditions to compare runs fairly.
