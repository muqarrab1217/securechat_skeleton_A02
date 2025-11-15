import json
import hashlib
from typing import Tuple, Optional
from pathlib import Path

from cryptography.hazmat.primitives import serialization


def _canonical_json_bytes(obj: dict) -> bytes:
    return (json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def cert_fingerprint_hex(cert_obj):
    raw = cert_obj.public_bytes(serialization.Encoding.DER)
    return hashlib.sha256(raw).hexdigest()


def append_transcript_line(transcript_path: str, seqno: int, ts_ms: int, ct: str,
    sig_b64: str, peer_cert_obj) -> None:
    entry = {
        "seqno": seqno,
        "ts": ts_ms,
        "ct": ct,
        "sig": sig_b64,
        "peer_fp": cert_fingerprint_hex(peer_cert_obj)
    }

    line_bytes = _canonical_json_bytes(entry)

    p = Path(transcript_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("ab") as f:
        f.write(line_bytes)


def compute_transcript_hash_and_bounds(transcript_path: str) -> Tuple[Optional[str], Optional[int], Optional[int]]:
    p = Path(transcript_path)
    if not p.exists() or p.stat().st_size == 0:
        return None, None, None

    digest = hashlib.sha256()
    first_seq = None
    last_seq = None

    with p.open("rb") as f:
        for line in f:
            digest.update(line)
            try:
                obj = json.loads(line.decode("utf-8"))
                seq = obj.get("seqno")
                if seq is not None:
                    if first_seq is None:
                        first_seq = seq
                    last_seq = seq
            except Exception:
                continue

    return digest.hexdigest(), first_seq, last_seq
