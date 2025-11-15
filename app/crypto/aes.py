"""AES-128(ECB)+PKCS#7 helpers (use library).""" 
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend
import base64

BLOCK_SIZE = 128

def pkcs7Pad(data: bytes):
    padder = sym_padding.PKCS7(BLOCK_SIZE).padder()
    return padder.update(data) + padder.finalize()

def pkcs7Unpad(padded: bytes):
    unpadder = sym_padding.PKCS7(BLOCK_SIZE).unpadder()
    return unpadder.update(padded) + unpadder.finalize()

def encryptEcbB64(key16: bytes, plaintext: bytes):
    assert len(key16) == 16
    cipher = Cipher(algorithms.AES(key16), modes.ECB(), backend=default_backend)
    encryptor = cipher.encryptor()
    ptPadded = pkcs7Pad(plaintext)
    ct = encryptor.update(ptPadded) + encryptor.finalize()
    return base64.b64encode(ct).decode("ascii")

def decryptEcbB64(key16: bytes, ctB64: str):
    assert len(key16) == 16
    ct = base64.b64decode(ctB64)
    cipher = Cipher(algorithms.AES(key16), modes.ECB(), backend=default_backend)
    decryptor = cipher.decryptor()
    ptPadded = decryptor.update(ct) + decryptor.finalize()
    return pkcs7Unpad(ptPadded)
