# Context-Bound Bluetooth Mesh Provisioning (CCN)

This repository contains a secure provisioning protocol prototype for Bluetooth Mesh that strengthens onboarding security against replay, relay, and misbinding attacks. It combines cryptographic context binding with an ML-based anomaly detector for behavioral monitoring.

## What This Project Implements

- A 5-message provisioning handshake between a Device and a Provisioner.
- Context-bound authentication using a transcript hash over session-critical fields.
- Session key derivation on both sides after successful verification.
- Simulated attacker behaviors for replay, relay, and misbinding scenarios.
- An Isolation Forest anomaly detector trained on normal session features.
- Unit and integration tests for crypto, packet structure, and attack resistance.

## Repository Layout

- provisioning_protocol/main.py
- End-to-end demo runner with normal flow, attack simulations, and ML phase.
- provisioning_protocol/device.py
	- Device-side provisioning logic.
- provisioning_protocol/provisioner.py
	- Provisioner-side state machine and verification logic.
- provisioning_protocol/channel.py
	- Simulated network channel with packet/timing metrics.
- provisioning_protocol/attacker.py
	- Attack simulation helpers (replay, relay tampering, misbinding spoof).
- provisioning_protocol/anomaly_detector.py
	- Feature extraction and unsupervised anomaly detection pipeline.
- provisioning_protocol/common/
	- constants.py: message IDs and fixed sizes.
	- packets.py: packet builders/parsers for all protocol messages.
	- crypto.py: transcript hash, auth token, session key, encryption helpers.
- provisioning_protocol/tests/
	- test_crypto.py: cryptographic utility tests.
	- test_packets.py: packet-format roundtrip tests.
	- test_attacks.py: full attack scenario integration tests.
- graphs/
	- Generated figures used for analysis and reporting.
- log.txt
	- Captured execution output from runs.

## Protocol Summary

The protocol uses a 5-message exchange:

1. Beacon (Device -> Provisioner)
2. Challenge (Provisioner -> Device)
3. Response (Device -> Provisioner)
4. Confirmation (Provisioner -> Device)
5. ACK (Device -> Provisioner)

### Core Security Idea: Context Binding

The Device computes a transcript hash over identifiers and fresh session values:

- DeviceID
- ProvisionerID
- NonceP
- NonceD
- Timestamp

The Response includes:

- transcript_hash (SHA-256)
- auth_token (AES-based proof using device secret)

The Provisioner recomputes the transcript hash from its local session context and rejects if any field was altered, stale, or mismatched.

## Threat Model and Defenses

### Replay Attack

- Attack: old Response is replayed in a new session.
- Defense: fresh NonceP/NonceD and transcript-bound auth cause verification failure.

### Relay Attack

- Attack: Challenge is intercepted and ProvisionerID is modified before reaching Device.
- Defense: Device and Provisioner derive different transcript hashes; Response rejected.

### Misbinding Attack

- Attack: attacker swaps Device identity fields in captured traffic.
- Defense: Provisioner checks DeviceID consistency across Beacon/Response and transcript.

## ML Layer (Behavioral Anomaly Detection)

The anomaly detector uses Isolation Forest to classify session behavior as normal or anomalous.

Representative features include:

- beacon_to_challenge latency
- challenge_to_response latency
- repeated device usage behavior
- session frequency in a rolling window
- packet size variance

This is a complementary layer that detects suspicious behavior patterns even when packet-level checks are bypassed or when attack traffic is noisy.

## Requirements

Python 3.10+ is recommended.

Install dependencies:

```bash
pip install pycryptodome numpy scikit-learn pytest
```

If you want to regenerate figures, also install plotting dependencies used by your analysis scripts (for example matplotlib).

## How To Run

From repository root:

```bash
python -m provisioning_protocol.main
```

Expected run phases:

- Phase A: normal provisioning and key-match verification.
- Phase B: replay simulation with rejection.
- Phase C: relay simulation with rejection.
- Phase D: misbinding simulation with rejection.
- Phase E: anomaly detector training/evaluation summary.

## Run Tests

Run complete test suite:

```bash
python -m pytest provisioning_protocol/tests -v
```

Or run specific modules:

```bash
python -m pytest provisioning_protocol/tests/test_crypto.py -v
python -m pytest provisioning_protocol/tests/test_packets.py -v
python -m pytest provisioning_protocol/tests/test_attacks.py -v
```

## Design Notes

- The protocol is implemented as a simulation environment, not a production Bluetooth stack integration.
- AES ECB is used in this prototype for deterministic block operations in token/key derivation helpers; production deployments should use modern authenticated encryption modes and strict key management.
- Timing and packet metrics from the channel are intentionally exposed to support observability and anomaly feature extraction.

## Current Repository State Notice

If you see merge conflict markers such as <<<<<<<, =======, and >>>>>>> in files, the repository is in the middle of a Git rebase/merge and should be resolved before running code or tests.

## Future Improvements

- Add a formal threat model document with explicit assumptions and attacker capabilities.
- Replace prototype crypto primitives with production-hardened constructions.
- Expand anomaly features and evaluate with larger adversarial datasets.
- Add CI checks for style, static analysis, and test coverage thresholds.
