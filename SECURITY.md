# SECURITY NOTES

## 1. Security Objective
The objective is to preserve ticket authenticity and protocol operation under partial compromise.
Specifically:
- at most one compromised authority must not be enough to forge accepted tickets
- one offline authority must not stop protocol progress
- payload tampering and replayed partial signatures must be rejected

## 2. Threat Model

### Assumptions
- At most one authority is compromised at a time.
- AES-256-CBC and SHA-256 remain cryptographically secure.
- Discrete logarithm in the selected Schnorr group remains hard.
- Attackers cannot compromise two authorities simultaneously in the protected model.

### Adversary capabilities addressed
- One malicious AS or TGS issues forged ticket shares.
- Network attacker modifies ticket payload fields.
- Replay of old partial signatures on new payloads.
- Leakage of one authority private signing key.
- One authority offline or unavailable.

### Out-of-model capabilities
- Compromise of two or more authorities in the same phase.
- Break of SHA-256, AES, or discrete-log assumptions.
- Host-level compromise of all authority nodes.

## 3. Security Invariants Enforced by Implementation
- Service accepts a ticket only when at least two signatures verify.
- Signatures must map to distinct authority IDs and current key versions.
- Ticket must decrypt and unpad correctly under AES-256-CBC and PKCS#7.
- Ticket must be within `(issue_ts + lifetime)` validity window.
- Ticket `service_id` must match the target service server.

These checks jointly block single-authority forgery, simple payload mutation, stale signatures, and expired or mismatched tickets.

## 4. Why One Compromised Authority Cannot Forge Tickets
- One compromised authority can generate at most one valid Schnorr share under its key.
- The service requires two independently valid shares.
- A fabricated second share fails verification against the second authority public key.
- Therefore, one compromise is insufficient to produce an accepted ticket.

## 5. Why Two Compromised Authorities Break Security
- The scheme target is exactly 2-of-3.
- If two private signing keys in the same trust set are compromised, attacker can create two valid signature shares.
- This satisfies the threshold predicate and can produce accepted forged tickets.
- This is a known threshold bound, not an implementation bug.

## 6. Why Two Independent Schnorr Signatures Improve Kerberos Trust
- Classical single-signer Kerberos creates one critical signing failure point.
- Independent authorities separate signing trust across nodes.
- The verifier checks each share independently with the corresponding public key.
- Compromise impact is localized to compromised authority keys, not automatically system-wide.

## 7. Nonce Reuse Risk in Schnorr
- Schnorr security critically depends on fresh per-signature nonce `k`.
- Reusing nonce across two signatures can leak the private key algebraically.
- Nonce generation for Schnorr signing uses OS-backed randomness (`SystemRandom`) per sign operation.
- Ticket session keys use OS-backed randomness (`os.urandom`) in both client protocol flow and attack payload generation.
- Operational requirement: do not replace RNG with deterministic or low-entropy source.

## 8. Key Leakage Impact Analysis
- Leakage of one authority private key: contained by threshold enforcement.
- Leakage of two authority private keys (same phase): threshold broken.
- Practical mitigation:
	- isolate authority hosts/processes
	- restrict filesystem access to private key files
	- rotate keys and key versions when leakage is suspected

## 9. Attack Scenario Mapping to Defenses
- Single malicious authority forge -> blocked by 2-of-3 verification.
- Modified payload -> blocked because signatures bind to payload hash.
- Replay old partial signature -> blocked because signature is message-specific.
- One key leakage -> blocked unless second authority is also compromised.
- One authority offline -> still works because any two authorities suffice.
- One valid signature only -> blocked by threshold check.

## 10. Attack Execution Modes and Offline Lifecycle
- `attacks.py` supports two execution modes:
	- Default mode: uses already-running AS/TGS/service processes.
	- Self-contained mode (`--self-contained`): starts and stops internal AS/TGS/service processes per scenario.
- In default mode, the `authority_offline` scenario actively takes down AS1 and leaves it offline after the scenario.
- Subsequent scenarios and normal client runs are expected to observe reduced AS availability until AS1 is restarted.
- AS-dependent attack scenarios are written to proceed with currently reachable AS authorities (minimum 2), preventing post-offline crash chains.

## 11. Performance-Security Tradeoff
- Additional cost compared to single-signer model:
	- more authority communication (collect >=2 shares)
	- more signature verifications at service
	- extra metadata in ticket payload
- Benefit:
	- compromise containment under one authority compromise
	- operational resilience under one authority outage
- Benchmark evidence in README shows overhead remains low on localhost (single-digit milliseconds per phase).

## 12. Observability and Auditability
- AS, TGS, and service servers log connection lifecycle (`CONNECT`, `REQUEST`, `RESPONSE`, `DISCONNECT`) with timestamps.
- Request logs include action and contextual identifiers (for example, `client_id`, `service_id` where available).
- Service logs include explicit rejection reasons, improving forensic clarity during attack demonstrations.

## 13. Residual Risks and Limitations
- This is a lab implementation and omits TLS channel protection.
- Public-key registry is local-file based for demonstration.
- Host compromise can still bypass process-level assumptions.
- No automated key rotation protocol is implemented (manual versioning model).
