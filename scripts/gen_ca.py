#!/usr/bin/env python3

"""Create Root CA (RSA + self-signed X.509) using cryptography.""" 
import argparse
from pathlib import Path
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--name", required=True, help="Common Name for Root CA")
    args = parser.parse_args()

    certsDir = Path("certs")
    certsDir.mkdir(exist_ok=True)

    caKey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, args.name),
    ])

    caCert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(caKey.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .sign(private_key=caKey, algorithm=hashes.SHA256())
    )

    keyPath = certsDir / "ca.key.pem"
    certPath = certsDir / "ca.cert.pem"

    with open(keyPath, "wb") as f:
        f.write(
            caKey.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )

    with open(certPath, "wb") as f:
        f.write(caCert.public_bytes(serialization.Encoding.PEM))

    print(f"Created Root CA:")
    print(f"    {keyPath}")
    print(f"    {certPath}")

if __name__ == "__main__":
    main()