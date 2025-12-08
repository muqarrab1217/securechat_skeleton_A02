# SecureChat Assignment #2 Report

## Introduction
This report documents the current status of the SecureChat PKI-enabled console chat system. Work so far focused on environment setup and dependency installation to enable further development and testing.

## Objectives
- Build a console-based Secure Chat that demonstrates confidentiality, integrity, authenticity, and non-repudiation at the application layer.
- Use explicit crypto (no TLS wrappers) with DH key exchange, AES for payload confidentiality, RSA signatures, and X.509 PKI validation.
- Support client/server messaging with session transcripts and signed receipts for non-repudiation.

## Approach
- Set up a Python virtual environment and installed project requirements per `requirements.txt`.
- Copied `.env.example` to `.env` to prepare configuration for database and cert paths.
- Planned to run MySQL via Docker using the provided credentials (`rootpass`, `scuser/scpass`, db `securechat`, port `3306`); Docker is not available on this host yet, so DB initialization is pending.
- Certificate generation scripts (`scripts/gen_ca.py`, `scripts/gen_cert.py`) are not yet executed; the `certs/` directory is currently empty.

## Reference from README (Assignment Brief)
- Goal: Build a console-based, PKI-enabled Secure Chat in Python that demonstrates confidentiality, integrity, authenticity, and non-repudiation (CIANR) at the application layer (no TLS wrappers).
- Provided skeleton: app (client/server, crypto: AES-128 PKCS#7, DH, RSA sign/verify, X.509 validation; common protocol models; storage for MySQL users and transcripts), scripts (Root CA and cert issuance), tests/manual notes, certs/transcripts placeholders, requirements, CI config.
- Setup steps: fork; create venv and install requirements; copy `.env.example` to `.env`; start MySQL (example Docker env vars for rootpass/scuser/scpass/db securechat/port 3306); init tables via `python -m app.storage.db --init`; generate CA and server/client certs; run `python -m app.server` and `python -m app.client`.
- Rules: no TLS/SSL wrappers; can use crypto libraries; do not commit secrets; maintain ≥10 meaningful commits.
- Deliverables: repo ZIP of fork, MySQL dump with sample records, updated README, report and test report DOCX.
- Test evidence checklist: Wireshark encrypted payloads only; BAD_CERT rejection; SIG_FAIL on tamper; REPLAY rejection by seqno; non-repudiation via transcript + signed SessionReceipt verified offline.

## Status and Results
- Environment: `.venv` created and dependencies installed successfully.
- Configuration: `.env` template copied; values need to be customized to match the chosen MySQL instance.
- Database: Not initialized (MySQL not running; Docker unavailable on this host at this time).
- Certificates: None generated yet; `certs/` is empty and `ca.cert.pem` was not found to extract results. Once the CA is generated, paste its details (subject, issuer, validity, key params) here.
- Services: `app.server` and `app.client` not started pending DB and certificate setup.

## Code Overview
- `app/client.py` and `app/server.py`: orchestrate the plaintext TCP workflow, driving the protocol message exchange and crypto operations explicitly (no TLS wrappers).
- `app/crypto/`: building blocks for crypto:
  - `dh.py` for Diffie-Hellman key exchange and derivation,
  - `aes.py` for AES-128 with PKCS#7 padding,
  - `sign.py` for RSA SHA-256 signing/verification (PKCS#1 v1.5),
  - `pki.py` for X.509 validation (CA signature, validity, CN matching).
- `app/common/`: shared protocol/message models (`protocol.py`) and utilities (`utils.py`) such as base64 helpers, timestamps, and SHA-256 hashing.
- `app/storage/`: `db.py` for MySQL-backed user store with salted SHA-256 passwords; `transcript.py` for append-only session transcripts and hashes to support non-repudiation.
- `scripts/`: `gen_ca.py` to create a Root CA (self-signed) and `gen_cert.py` to issue server/client certs signed by that CA.

## Next Steps
- Provide or install a MySQL instance (Docker Desktop or native). Start MySQL with the expected credentials or adjust `.env` to match your instance.
- Run `python -m app.storage.db --init` to create tables once MySQL is reachable.
- Implement and run the certificate scripts:
  - `python scripts/gen_ca.py --name "FAST-NU Root CA"`
  - `python scripts/gen_cert.py --cn server.local --out certs/server`
  - `python scripts/gen_cert.py --cn client.local --out certs/client`
- Start server and client in separate terminals:
  - `python -m app.server`
  - `python -m app.client`
- Perform manual tests (Wireshark capture, BAD_CERT, SIG_FAIL, REPLAY, SessionReceipt verification) and collect evidence for submission.

