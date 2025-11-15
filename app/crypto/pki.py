"""X.509 validation: signed-by-CA, validity window, CN/SAN.""" 

from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import datetime

def loadPemCert(pathOrBytes):
    if isinstance(pathOrBytes, (bytes, bytearray)):
        data = bytes(pathOrBytes)
    else:
        with open(str(pathOrBytes), "rb") as f:
            data = f.read()
    return x509.load_pem_x509_certificate(data)

def loadPemPrivateKey(path, password = None):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=password)
    
def certPubKey(cert: x509.Certificate):
    return cert.public_key()

def verifySignature(cert: x509.Certificate, issuerCert: x509.Certificate):
    issuerPub = issuerCert.public_key()
    try:
        issuerPub.verify(
            signature=cert.signature,
            data=cert.tbs_certificate_bytes,
            padding=padding.PKCS1v15(),
            algorithm=cert.signature_hash_algorithm
        )
        return True, ""
    except Exception as e:
        return False, f"bad signature: {e}"
    
def checkValidity(cert: x509.Certificate):
    now = datetime.datetime.utcnow()
    if now < cert.not_valid_before:
        return False, f"not yet valid (not_before={cert.not_valid_before.isoformat()})"
    if now > cert.not_valid_after:
        return False, f"expired (not_after={cert.not_valid_after.isoformat()})"
    return True, ""

def checkCn(cert: x509.Certificate, expectedCn: str):
    if expectedCn is None:
        return True, ""
    
    try:
        cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    except Exception:
        return False, "no CN in subject"
    
    if cn != expectedCn:
        return False, f"CN mismatch: got={cn} expected={expectedCn}"
    return True, ""

def verifyCert(certPemPathOrBytes, caCertPemPathOrBytes, expectedCn: str = None):
    try:
        cert = loadPemCert(certPemPathOrBytes)
    except Exception as e:
        return False, f"unable to parse cert: {e}"
    
    try:
        caCert = loadPemCert(caCertPemPathOrBytes)
    except Exception as e:
        return False, f"unable to parse CA cert: {e}"

    ok, reason = verifySignature(cert, caCert)
    if not ok:
        return False, reason
    
    ok, reason = checkValidity(cert)
    if not ok:
        return False, reason
    
    ok, reason = checkCn(cert, expectedCn)
    if not ok:
        return False, reason
    
    return True, ""