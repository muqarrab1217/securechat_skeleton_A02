#!/usr/bin/env python3
import json
import sys
import hashlib
import base64
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

def load_cert(path):
    with open(path, "rb") as f:
        data = f.read()
    return x509.load_pem_x509_certificate(data)

def compute_fingerprint(cert):
    return cert.fingerprint(hashes.SHA256()).hex()

def compute_transcript_hash(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(4096)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

def verify_sig_bytes(pub, message_bytes: bytes, sig_b64: str):
    try:
        sig = base64.b64decode(sig_b64)
    except Exception as e:
        return False, f"bad base64 sig: {e}"
    try:
        pub.verify(sig, message_bytes, padding.PKCS1v15(), hashes.SHA256())
        return True, "valid"
    except Exception as e:
        return False, str(e)

def main():
    if len(sys.argv) != 4:
        print("Usage: verify_receipt.py <transcript.log> <receipt.json> <signer_cert.pem>")
        sys.exit(1)

    transcript_path = sys.argv[1]
    receipt_path = sys.argv[2]
    signer_cert_path = sys.argv[3]

    print("=== Offline Verification Tool ===")
    print(f"Transcript: {transcript_path}")
    print(f"Receipt:    {receipt_path}")
    print(f"Cert:       {signer_cert_path}")
    print("---------------------------------")

    local_transcript_hash = compute_transcript_hash(transcript_path)
    print(f"[+] Local Transcript SHA256: {local_transcript_hash}")

    with open(receipt_path, "r", encoding="utf-8") as f:
        receipt = json.load(f)

    # minimal field checks
    required = ["type", "my_fp", "peer_fp", "transcript_sha256", "first_seq", "last_seq", "sig"]
    for r in required:
        if r not in receipt:
            print(f"[FAIL] Receipt missing field: {r}")
            sys.exit(1)

    # transcript match
    if receipt["transcript_sha256"] != local_transcript_hash:
        print("[FAIL] Transcript hash mismatch!")
        print(f"  Receipt: {receipt['transcript_sha256']}")
        print(f"  Local:   {local_transcript_hash}")
        sys.exit(1)
    else:
        print("[+] Transcript hash matches receipt")

    signer_cert = load_cert(signer_cert_path)
    signer_fp = compute_fingerprint(signer_cert)
    print(f"[+] Signer cert fingerprint: {signer_fp}")

    if receipt["my_fp"] != signer_fp:
        print("[FAIL] Certificate fingerprint mismatch (my_fp != signer_fp)")
        sys.exit(1)
    else:
        print("[+] Fingerprint matches receipt.my_fp")

    pub = signer_cert.public_key()
    sig_b64 = receipt["sig"]

    # Method 1: verify signature over transcript_sha256 only
    m1 = receipt["transcript_sha256"].encode("ascii")
    ok1, msg1 = verify_sig_bytes(pub, m1, sig_b64)
    if ok1:
        print("[+] Signature valid (signature over transcript_sha256)")
        print("RESULT: PASS — Receipt verified successfully.")
        return

    # Method 2: verify signature over concatenated canonical fields (fallback)
    concat = (
        receipt["transcript_sha256"] +
        receipt.get("my_fp","") +
        receipt.get("peer_fp","") +
        str(receipt.get("first_seq","")) +
        str(receipt.get("last_seq",""))
    ).encode("utf-8")
    ok2, msg2 = verify_sig_bytes(pub, concat, sig_b64)
    if ok2:
        print("[+] Signature valid (signature over transcript_sha256||my_fp||peer_fp||first_seq||last_seq)")
        print("RESULT: PASS — Receipt verified successfully (concat form).")
        return

    # neither method worked
    print("[FAIL] Receipt signature INVALID for both tried canonicalizations.")
    print(" - verify over transcript_sha256 gave:", msg1)
    print(" - verify over concatenation gave:", msg2)
    sys.exit(1)

if __name__ == "__main__":
    main()
