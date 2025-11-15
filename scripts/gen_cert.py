#!/usr/bin/env python3
"""Issue server/client cert signed by Root CA (SAN=DNSName(CN)).""" 

import argparse
from pathlib import Path
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime

def loadCA():
    with open("certs/ca.key.pem", "rb") as f:
        caKey = serialization.load_pem_private_key(f.read(), password=None)
    
    with open("certs/ca.cert.pem", "rb") as f:
        caCert = x509.load_pem_x509_certificate(f.read())

    return caKey, caCert

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cn", required=True, help="Common Name for the certificate")
    parser.add_argument("--out", required=True, help="Output path prefix")
    args = parser.parse_args()

    outPrefix = Path(args.out)
    outPrefix.parent.mkdir(exist_ok=True)

    caKey, caCert = loadCA()
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, args.cn),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(caCert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365 * 3))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .sign(private_key=caKey, algorithm=hashes.SHA256())
    )

    keyPath = f"{args.out}.key.pem"
    certPath = f"{args.out}.cert.pem"

    with open(keyPath, "wb") as f:
        f.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )

    with open(certPath, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"Issued Certificate:")
    print(f"    {keyPath}")
    print(f"    {certPath}")

if __name__ == "__main__":
    main()