#!/usr/bin/env python3
"""
Skapar ett certifikat med UPN i SAN för en befintlig publik nyckel.

Används för att skriva ett korrekt PIV-cert till YubiKey slot 9A utan att
röra den privata nyckeln som redan finns på kortet.

Användning:
  python3 issue-yubikey-cert.py \\
      <pub_key.pem>   \\   # publik nyckel extraherad ur befintligt YubiKey-cert
      <ca.crt>        \\   # CA-certifikat (PEM)
      <ca.key>        \\   # CA:ns privata nyckel (PEM, okrypterad)
      <upn>           \\   # t.ex. alun@company.com
      <out_cert.pem>  \\   # utdata: nytt cert att importera till YubiKey
      [<certs.json>]       # valfritt: uppdatera certs.json för CUPS TEST_MODE
"""

import sys
import json
import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

UPN_OID = x509.ObjectIdentifier("1.3.6.1.4.1.311.20.2.3")


def _upn_der(upn: str) -> bytes:
    """DER-kodar UPN som UTF8String: tag=0x0C, length, utf8-bytes."""
    encoded = upn.encode("utf-8")
    return bytes([0x0C, len(encoded)]) + encoded


def main() -> None:
    if len(sys.argv) < 6:
        print(__doc__)
        sys.exit(1)

    pub_key_path  = Path(sys.argv[1])
    ca_cert_path  = Path(sys.argv[2])
    ca_key_path   = Path(sys.argv[3])
    upn           = sys.argv[4]
    out_cert_path = Path(sys.argv[5])
    certs_json    = Path(sys.argv[6]) if len(sys.argv) > 6 else None

    # Ladda den publika nyckeln ur YubiKey-certets PEM-pubkey-export
    pub_key = serialization.load_pem_public_key(pub_key_path.read_bytes())

    # Ladda CA
    ca_cert = x509.load_pem_x509_certificate(ca_cert_path.read_bytes())
    ca_key  = serialization.load_pem_private_key(ca_key_path.read_bytes(), password=None)

    now = datetime.datetime.now(datetime.timezone.utc)

    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME,      upn.split("@")[0]),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS,    upn),
        ]))
        .issuer_name(ca_cert.subject)
        .public_key(pub_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.OtherName(UPN_OID, _upn_der(upn)),   # Microsoft UPN OID
                x509.RFC822Name(upn),
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
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,  key_encipherment=True,
                content_commitment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    out_cert_path.write_bytes(cert_pem)
    print(f"Certifikat:  {out_cert_path}")
    print(f"UPN:         {upn}")
    print(f"Utfärdat av: {ca_cert.subject.rfc4514_string()}")
    print(f"Giltigt tom: {cert.not_valid_after_utc.strftime('%Y-%m-%d')}")

    # Verifiera att UPN kan extraheras (testar terminal-appens logik)
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    for name in san.value:
        if isinstance(name, x509.OtherName) and name.type_id == UPN_OID:
            raw = name.value
            assert raw[0] == 0x0C, "Fel ASN.1-tagg"
            extracted = raw[2 : 2 + raw[1]].decode("utf-8")
            assert extracted == upn, f"UPN-mismatch: {extracted!r} != {upn!r}"
            print(f"UPN-verifiering: OK ({extracted})")

    # Skriv certs.json för CUPS-backend (TEST_MODE)
    if certs_json:
        existing = {}
        if certs_json.exists():
            existing = json.loads(certs_json.read_text())
        existing[upn] = cert_pem.decode()
        certs_json.write_text(json.dumps(existing, indent=2))
        print(f"certs.json:  {certs_json} (uppdaterad)")


if __name__ == "__main__":
    main()
