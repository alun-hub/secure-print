#!/usr/bin/env python3
"""
Genererar testcertifikat med UPN i Subject Alternative Name.

UPN sätts som OtherName med OID 1.3.6.1.4.1.311.20.2.3 (Microsoft UPN),
kodad som DER UTF8String – exakt det format som app.py och s3print förväntar sig.

Utdata (i katalog angiven som argument, default: test/pki/):
  ca.key      CA:ns privata nyckel
  ca.crt      CA-certifikat
  user.key    Användarens privata nyckel
  user.crt    Användarens certifikat (med UPN i SAN)
  certs.json  { "testuser@company.com": "<PEM>" }  – monteras i CUPS-container
"""

import sys
import json
import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

UPN       = "testuser@company.com"
UPN_OID   = x509.ObjectIdentifier("1.3.6.1.4.1.311.20.2.3")
OUT_DIR   = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).parent / "pki"


def _gen_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _save_key(key, path: Path) -> None:
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )


def _save_cert(cert, path: Path) -> None:
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def _upn_der(upn: str) -> bytes:
    """
    Kodar UPN som DER UTF8String: tag=0x0C, length, utf8-bytes.
    Detta är vad som läggs i OtherName.value och vad app.py parsar.
    """
    encoded = upn.encode("utf-8")
    return bytes([0x0C, len(encoded)]) + encoded


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    now = datetime.datetime.now(datetime.timezone.utc)

    # ── CA ────────────────────────────────────────────────────────────────
    ca_key = _gen_key()
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Secure Print Test CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    _save_key(ca_key,  OUT_DIR / "ca.key")
    _save_cert(ca_cert, OUT_DIR / "ca.crt")
    print(f"CA:         {OUT_DIR / 'ca.crt'}")

    # ── Användarcertifikat med UPN i SAN ──────────────────────────────────
    user_key = _gen_key()
    user_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME,         "Test User"),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS,        UPN),
        ]))
        .issuer_name(ca_name)
        .public_key(user_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([
                # UPN i OtherName – det här är vad smartkortet innehåller
                x509.OtherName(UPN_OID, _upn_der(UPN)),
                # RFC822Name som extra identifierare
                x509.RFC822Name(UPN),
            ]),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([
                x509.ExtendedKeyUsageOID.CLIENT_AUTH,
                x509.ExtendedKeyUsageOID.EMAIL_PROTECTION,
            ]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    _save_key(user_key,   OUT_DIR / "user.key")
    _save_cert(user_cert,  OUT_DIR / "user.crt")
    print(f"Användarcert: {OUT_DIR / 'user.crt'}  (UPN: {UPN})")

    # Verifiera att UPN kan extraheras (testar app.py-logiken)
    san = user_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    for name in san.value:
        if isinstance(name, x509.OtherName) and name.type_id == UPN_OID:
            raw = name.value
            assert raw[0] == 0x0C, "Fel ASN.1-tagg"
            extracted = raw[2 : 2 + raw[1]].decode("utf-8")
            assert extracted == UPN, f"UPN-mismatch: {extracted!r} != {UPN!r}"
            print(f"UPN-verifiering OK: {extracted}")

    # ── certs.json ────────────────────────────────────────────────────────
    cert_pem = user_cert.public_bytes(serialization.Encoding.PEM).decode()
    certs_json = OUT_DIR.parent / "certs.json"
    certs_json.write_text(json.dumps({UPN: cert_pem}, indent=2))
    print(f"certs.json: {certs_json}")

    print("\nKlart! Kör nu: bash test/setup.sh")


if __name__ == "__main__":
    main()
