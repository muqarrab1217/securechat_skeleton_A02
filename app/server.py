import struct
import json
import os
import socket
import secrets
import hashlib
import base64
import hmac
import threading
import time
import datetime
import queue

from app.common.protocol import Hello, jsonEncode, jsonDecode
from app.crypto.pki import loadPemCert, verifyCert, loadPemPrivateKey, certPubKey
from app.crypto.dh import generatePrivateKey, publicFromPrivate, deriveSharedKey
from app.crypto.aes import encryptEcbB64, decryptEcbB64
from app.storage.db import get_conn
from app.storage.transcript import append_transcript_line, compute_transcript_hash_and_bounds, cert_fingerprint_hex

from cryptography.hazmat.primitives.asymmetric import padding, utils
from cryptography.hazmat.primitives import hashes

CA_CERT = os.getenv("CA_CERT", "certs/ca.cert.pem")
SERVER_CERT = os.getenv("SERVER_CERT", "certs/server.cert.pem")
SERVER_KEY = os.getenv("SERVER_KEY", "certs/server.key.pem")
SERVER_HOST = os.getenv("SERVER_HOST", "127.0.0.1")
SERVER_PORT = int(os.getenv("SERVER_PORT", "9000"))

def timestamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

SESSION_ID = timestamp()

TRANSCRIPT_DIR = "transcripts"
RECEIPT_DIR = "server_receipts"
os.makedirs(TRANSCRIPT_DIR, exist_ok=True)
os.makedirs(RECEIPT_DIR, exist_ok=True)

TRANSCRIPT_FILE = os.path.join(TRANSCRIPT_DIR, f"transcript_server_{SESSION_ID}.log")
OWN_RECEIPT_FILE = os.path.join(RECEIPT_DIR, f"server_receipt_{SESSION_ID}.json")
PEER_RECEIPT_FILE = os.path.join(RECEIPT_DIR, f"server_peer_receipt_{SESSION_ID}.json")

def sendMsgSock(sock, objBytes: bytes):
    length = len(objBytes)
    hdr = struct.pack("!I", length)
    sock.sendall(hdr + objBytes)

def recvMsgSock(sock):
    hdr = b""
    while len(hdr) < 4:
        chunk = sock.recv(4 - len(hdr))
        if not chunk:
            raise ConnectionError("socket closed while reading header")
        hdr += chunk

    length = struct.unpack("!I", hdr)[0]

    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise ConnectionError("socket closed while reading body")
        data += chunk
    return data

def sign_bytes_rsa(privkey, data: bytes) -> bytes:
    return privkey.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

def verify_signature_with_pubkey(pubkey, data: bytes, sig: bytes) -> bool:
    try:
        pubkey.verify(sig, data, padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False

def chat_send_loop(conn, session_key: bytes, server_priv, send_state, own_cert_obj):
    try:
        while True:
            line = input()
            if not line:
                continue
            if line.strip().lower() == "/quit":
                with send_state["lock"]:
                    send_state["quit"] = True
                return

            with send_state["lock"]:
                seqno = send_state["next_seq"]
                send_state["next_seq"] += 1

            ts = int(time.time() * 1000)
            ct = encryptEcbB64(session_key, line.encode("utf-8"))

            # Build canonical message bytes for hashing
            msg_bytes_for_hash = f"{seqno}{ts}{ct}".encode("utf-8")
            # Compute SHA-256 digest (explicit)
            digest = hashlib.sha256(msg_bytes_for_hash).digest()

            # Sign the digest using Prehashed(SHA256)
            sig = server_priv.sign(digest, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256()))
            sig_b64 = base64.b64encode(sig).decode("ascii")

            msg = {
                "type": "msg",
                "seqno": seqno,
                "ts": ts,
                "ct": ct,
                "sig": sig_b64
            }

            sendMsgSock(conn, json.dumps(msg).encode("utf-8"))

            try:
                append_transcript_line(TRANSCRIPT_FILE, seqno, ts, ct, sig_b64, own_cert_obj)
            except Exception as e:
                print("[server] transcript append (send) failed:", e)
    except Exception as e:
        print("[server][send] exception:", e)
        return

def chat_recv_loop(conn, session_key: bytes, client_pubkey, recv_state, peer_cert_obj, stop_event: threading.Event, receipt_q: "queue.Queue"):
    try:
        while not stop_event.is_set():
            try:
                raw = recvMsgSock(conn)
            except ConnectionError:
                break
            except Exception:
                break
            if not raw:
                break
            msg = json.loads(raw.decode("utf-8"))
            if msg.get("type") == "msg":
                seqno = int(msg["seqno"])
                ts = int(msg["ts"])
                ct = msg["ct"]
                sig_b64 = msg["sig"]
                sig = base64.b64decode(sig_b64)

                with recv_state["lock"]:
                    last = recv_state["last_seq"]
                    if seqno <= last:
                        print("[server] REPLAY detected:", seqno)
                        continue
                    recv_state["last_seq"] = seqno

                msg_bytes_for_hash = f"{seqno}{ts}{ct}".encode("utf-8")
                digest = hashlib.sha256(msg_bytes_for_hash).digest()

                try:
                    # Verify signature against the pre-hashed digest
                    client_pubkey.verify(sig, digest, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256()))
                except Exception:
                    print("[server] signature FAIL:", seqno)
                    continue

                try:
                    pt = decryptEcbB64(session_key, ct)
                    print(f"[peer] ({seqno}) {pt.decode('utf-8')}")
                except Exception:
                    print("[server] decrypt failed:", seqno)
                    continue

                try:
                    append_transcript_line(TRANSCRIPT_FILE, seqno, ts, ct, sig_b64, peer_cert_obj)
                except Exception as e:
                    print("[server] transcript append (recv) failed:", e)

            elif msg.get("type") == "receipt":
                try:
                    receipt_q.put_nowait(msg)
                except Exception:
                    pass
            else:
                continue
    finally:
        stop_event.set()

def build_receipt(privkey, role_label: str, transcript_path: str, my_fp: str, peer_fp: str):
    digest_hex, first_seq, last_seq = compute_transcript_hash_and_bounds(transcript_path)
    if digest_hex is None:
        digest_hex = ""

    ts = int(time.time() * 1000)
    sig = privkey.sign(digest_hex.encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
    sig_b64 = base64.b64encode(sig).decode("ascii")

    return digest_hex, {
        "type": "receipt",
        "peer": role_label,
        "my_fp": my_fp,
        "peer_fp": peer_fp,
        "first_seq": first_seq,
        "last_seq": last_seq,
        "transcript_sha256": digest_hex,
        "ts": ts,
        "sig": sig_b64
    }


def send_receipt(sock, receipt: dict):
    sendMsgSock(sock, json.dumps(receipt).encode("utf-8"))


def recv_and_verify_receipt_from_queue(sock, peer_pubkey, expected_peer_fp: str, local_transcript_hex: str, receipt_q: "queue.Queue", timeout=10):
    try:
        msg = receipt_q.get_nowait()
    except queue.Empty:
        try:
            msg = receipt_q.get(timeout=timeout)
        except queue.Empty:
            try:
                raw = recvMsgSock(sock)
            except Exception as e:
                return False, None, f"no receipt received: {e}"
            try:
                msg = json.loads(raw.decode("utf-8"))
            except:
                return False, None, "invalid receipt JSON"

    if msg.get("type") != "receipt":
        return False, msg, "unexpected message type"

    if msg.get("peer_fp") != expected_peer_fp:
        return False, msg, "peer fingerprint mismatch"

    peer_digest = msg["transcript_sha256"]
    sig = base64.b64decode(msg["sig"])

    try:
        peer_pubkey.verify(sig, peer_digest.encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
    except:
        return False, msg, "signature verification failed"

    if local_transcript_hex != peer_digest:
        return False, msg, "transcript hash mismatch"

    return True, msg, "receipt OK"

def handleClient(conn, addr):
    print(f"[server] connection from {addr}")
    try:
        raw = recvMsgSock(conn)
        msg = jsonDecode(raw)

        if msg.get("type") != "hello":
            conn.close()
            return

        clientCertPem = msg.get("certPem", "").encode("utf-8")
        ok, reason = verifyCert(clientCertPem, CA_CERT)
        if not ok:
            sendMsgSock(conn, json.dumps({"type": "error", "code": "BAD_CERT"}).encode("utf-8"))
            conn.close()
            return

        client_cert_obj = loadPemCert(clientCertPem)
        client_pubkey = certPubKey(client_cert_obj)

        with open(SERVER_CERT, "rb") as f:
            serverCertPemBytes = f.read()

        sendMsgSock(conn, jsonEncode(Hello(certPem=serverCertPemBytes.decode("utf-8"), nonce="srv-nonce-1")))

        raw = recvMsgSock(conn)
        msg = jsonDecode(raw)

        if msg.get("type") != "dh_client":
            conn.close()
            return

        A = int(msg["A"], 16)
        b = generatePrivateKey()
        B = publicFromPrivate(b)
        sendMsgSock(conn, json.dumps({"type": "dh_server", "B": format(B, 'x')}).encode("utf-8"))

        key16 = deriveSharedKey(b, A)

        raw = recvMsgSock(conn)
        msg = jsonDecode(raw)

        plaintext = decryptEcbB64(key16, msg["ct"])
        payload = json.loads(plaintext.decode("utf-8"))

        if payload.get("type") == "register":
            username = payload["username"]
            email = payload["email"]
            password = payload["password"]

            salt = secrets.token_bytes(16)
            pwd_hash = hashlib.sha256(salt + password.encode("utf-8")).hexdigest()

            connDB = get_conn()
            with connDB.cursor() as cur:
                try:
                    cur.execute(
                        "INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s,%s,%s,%s)",
                        (email, username, salt, pwd_hash)
                    )
                    resp = {"status": "ok", "msg": "registered"}
                except Exception as e:
                    resp = {"status": "error", "msg": str(e)}

            sendMsgSock(conn, json.dumps({"type": "enc", "ct": encryptEcbB64(key16, json.dumps(resp).encode("utf-8"))}).encode("utf-8"))

        elif payload.get("type") == "login":
            username = payload["username"]
            password = payload["password"]

            connDB = get_conn()
            with connDB.cursor() as cur:
                cur.execute("SELECT salt,pwd_hash FROM users WHERE username=%s", (username,))
                row = cur.fetchone()

            if not row:
                resp = {"status": "error", "msg": "no such user"}
            else:
                salt, storedHash = row
                if isinstance(salt, memoryview):
                    salt = salt.tobytes()
                if isinstance(storedHash, (bytes, bytearray)):
                    storedHash = storedHash.decode("utf-8")

                chk = hashlib.sha256(salt + password.encode("utf-8")).hexdigest()
                if hmac.compare_digest(chk, storedHash):
                    resp = {"status": "ok", "msg": "login successful"}
                else:
                    resp = {"status": "error", "msg": "bad credentials"}

            sendMsgSock(conn, json.dumps({"type": "enc", "ct": encryptEcbB64(key16, json.dumps(resp).encode("utf-8"))}).encode("utf-8"))

        server_priv = loadPemPrivateKey(SERVER_KEY)

        raw = recvMsgSock(conn)
        msg = jsonDecode(raw)

        if msg.get("type") != "dh_session":
            conn.close()
            return

        A_hex = msg["A"]
        sig = base64.b64decode(msg["sig"])

        if not verify_signature_with_pubkey(client_pubkey, A_hex.encode("utf-8"), sig):
            sendMsgSock(conn, json.dumps({"type": "error", "code": "SIG_FAIL"}).encode("utf-8"))
            conn.close()
            return

        bs = generatePrivateKey()
        B_hex = format(publicFromPrivate(bs), "x")
        sig_B = sign_bytes_rsa(server_priv, B_hex.encode("utf-8"))
        sig_B_b64 = base64.b64encode(sig_B).decode("ascii")

        sendMsgSock(conn, json.dumps({"type": "dh_session_server", "B": B_hex, "sig": sig_B_b64}).encode("utf-8"))

        session_key = deriveSharedKey(bs, int(A_hex, 16))

        server_cert_obj = loadPemCert(serverCertPemBytes)

        send_state = {"next_seq": 1, "lock": threading.Lock(), "quit": False}
        recv_state = {"last_seq": 0, "lock": threading.Lock()}
        recv_stop = threading.Event()
        receipt_q = queue.Queue()

        my_fp = cert_fingerprint_hex(server_cert_obj)
        peer_fp = cert_fingerprint_hex(client_cert_obj)

        sender = threading.Thread(target=chat_send_loop, args=(conn, session_key, server_priv, send_state, server_cert_obj))
        receiver = threading.Thread(target=chat_recv_loop, args=(conn, session_key, client_pubkey, recv_state, client_cert_obj, recv_stop, receipt_q))
        sender.start()
        receiver.start()

        sender.join()
        recv_stop.set()
        receiver.join(timeout=2)

        local_hex, our_receipt = build_receipt(server_priv, "server", TRANSCRIPT_FILE, my_fp, peer_fp)
        with open(OWN_RECEIPT_FILE, "w") as f:
            json.dump(our_receipt, f, indent=2)

        send_receipt(conn, our_receipt)
        ok, peer_receipt, msg = recv_and_verify_receipt_from_queue(conn, client_pubkey, my_fp, local_hex, receipt_q, timeout=10)

        with open(PEER_RECEIPT_FILE, "w") as f:
            json.dump(peer_receipt if peer_receipt else {}, f, indent=2)

        if not ok:
            print("[server] peer receipt verification failed:", msg)
            try:
                print("[debug] local_hash:", local_hex)
                if peer_receipt:
                    print("[debug] peer_digest:", peer_receipt.get("transcript_sha256"))
            except:
                pass
        else:
            print("[server] peer receipt verified OK")

        try:
            conn.close()
        except:
            pass

    except Exception as e:
        print("[server] exception:", e)
        try:
            conn.close()
        except:
            pass


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((SERVER_HOST, SERVER_PORT))
    sock.listen(5)
    print(f"[server] listening on {SERVER_HOST}:{SERVER_PORT}")

    while True:
        conn, addr = sock.accept()
        handleClient(conn, addr)


if __name__ == "__main__":
    main()
