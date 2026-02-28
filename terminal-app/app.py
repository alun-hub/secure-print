#!/usr/bin/env python3
"""
Secure Print Terminal

Lokal Flask-app som körs på den tunna terminalen vid skrivaren.
Chromium startas i kiosk-läge mot http://localhost:5000

Flöde:
  1. Sätt i smartkort
  2. Ange PIN → UPN extraheras ur certifikatet
  3. Välj jobb från listan → dekrypteras med smartkortets privata nyckel
  4. Skrivs ut på lokal skrivare
"""

import base64
import hashlib
import json
import os
import re
import sys
import subprocess
import tempfile
import threading
import time
import logging
import secrets
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import boto3
import psycopg2
import psycopg2.extras
import pkcs11
import pkcs11.util.rsa
from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.x509 import load_der_x509_crl
from flask import Flask, jsonify, render_template, request, session
from botocore.config import Config

# ---------------------------------------------------------------------------
# Konfiguration från miljövariabler
# ---------------------------------------------------------------------------
DATABASE_URL    = os.environ["DATABASE_URL"]
S3_ENDPOINT     = os.environ["S3_ENDPOINT"]
S3_ACCESS_KEY   = os.environ["S3_ACCESS_KEY"]
S3_SECRET_KEY   = os.environ["S3_SECRET_KEY"]
S3_BUCKET       = os.environ["S3_BUCKET"]
LOCAL_PRINTER   = os.environ.get("LOCAL_PRINTER", "default")
TERMINAL_ID     = os.environ.get("TERMINAL_ID", "terminal-unknown")
PKCS11_LIB         = os.environ.get("PKCS11_LIB", "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so")

# Revokationskontroll: "ocsp" (standard), "strict" (fel om status okänd), "none" (inaktivt)
REVOCATION_CHECK   = os.environ.get("REVOCATION_CHECK", "ocsp")
REVOCATION_CA_FILE = os.environ.get("REVOCATION_CA_FILE", "/etc/ssl/certs/ca-certificates.crt")
REVOCATION_TIMEOUT = int(os.environ.get("REVOCATION_TIMEOUT", "10"))

# ---------------------------------------------------------------------------
# Hjälpfunktioner för utskriftsinställningar
# ---------------------------------------------------------------------------

_SAFE_KEY   = re.compile(r'^[a-zA-Z0-9_\-]+$')
_SAFE_VALUE = re.compile(r'^[a-zA-Z0-9_\-\./: ]+$')


def build_lpr_cmd(printer: str, copies: int, options_json: str) -> list[str]:
    """Bygger lpr-argumentlistan med -o key=value för varje sparad option."""
    cmd = ["lpr", "-P", printer, "-#", str(copies)]
    opts = json.loads(options_json or '{}')
    for key, value in opts.items():
        if (key != 'copies'
                and _SAFE_KEY.match(key)
                and _SAFE_VALUE.match(str(value))):
            cmd.extend(["-o", f"{key}={value}"])
    return cmd


def _detect_print_suffix(data: bytes) -> str:
    """Detekterar filformat ur magic bytes och returnerar lämplig filändelse."""
    if data[:5] == b'%PDF-':
        return '.pdf'
    if data[:2] == b'%!':
        return '.ps'
    return '.dat'


def summarize_options(opts: dict) -> str:
    """Genererar läsbar sammanfattning av utskriftsinställningar."""
    parts = []
    sides = opts.get('sides', '')
    if 'two-sided' in sides:
        parts.append('Dubbelsidig')
    media = opts.get('media', '')
    if media:
        if 'a4' in media.lower():
            parts.append('A4')
        elif 'a3' in media.lower():
            parts.append('A3')
        elif 'letter' in media.lower():
            parts.append('Letter')
        else:
            parts.append(media)
    color = opts.get('print-color-mode', '')
    if color == 'monochrome':
        parts.append('Svartvitt')
    elif color == 'color':
        parts.append('Färg')
    nup = opts.get('number-up', '')
    if nup and nup != '1':
        parts.append(f'{nup}-up')
    return ' · '.join(parts) if parts else ''


# ---------------------------------------------------------------------------
# Loggning
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Flask
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = secrets.token_bytes(32)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["PERMANENT_SESSION_LIFETIME"] = 300       # 5 minuter
app.config["SESSION_REFRESH_EACH_REQUEST"] = True    # förläng session vid varje anrop

# ---------------------------------------------------------------------------
# Sessionskryptering – PIN lagras aldrig i klartext i cookie-payloaden
# ---------------------------------------------------------------------------

def _session_cipher() -> Fernet:
    """Deriverar en Fernet-nyckel ur appens secret_key för att kryptera PIN."""
    key = hashlib.sha256(app.secret_key + b":pin-enc-v1").digest()
    return Fernet(base64.urlsafe_b64encode(key))


# ---------------------------------------------------------------------------
# Smartkortsövervakning (bakgrundstråd)
# ---------------------------------------------------------------------------
_card_lock    = threading.Lock()
_card_present = False


def _check_card_present() -> bool:
    """Kontrollerar om ett smartkort är isatt via pkcs11."""
    try:
        lib   = pkcs11.lib(PKCS11_LIB)
        slots = lib.get_slots(token_present=True)
        return len(list(slots)) > 0
    except Exception:
        return False


def _card_monitor():
    """Bakgrundstråd: rensa session när kortet tas ut."""
    global _card_present
    while True:
        present = _check_card_present()
        with _card_lock:
            if _card_present and not present:
                log.info("Smartkort borttaget – session rensas")
                # Flask sessions är per-request, men vi sätter en flagga
                # som frontendens polling plockar upp
                _card_present = False
            elif not _card_present and present:
                log.info("Smartkort isatt")
                _card_present = True
        time.sleep(1)


threading.Thread(target=_card_monitor, daemon=True).start()


# ---------------------------------------------------------------------------
# Smartkortsfunktioner
# ---------------------------------------------------------------------------

UPN_OID = "1.3.6.1.4.1.311.20.2.3"  # Microsoft UPN i SAN


def _extract_upn(cert_pem: str) -> str:
    """Extraherar UPN ur certifikatets Subject Alternative Name."""
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    san  = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)

    for name in san.value:
        if isinstance(name, x509.OtherName):
            if name.type_id.dotted_string == UPN_OID:
                raw = name.value          # DER-kodad UTF8String
                if raw[0] == 0x0C:        # UTF8String ASN.1-tagg
                    length = raw[1]
                    return raw[2 : 2 + length].decode("utf-8")

    raise ValueError("UPN ej funnet i certifikatet")


def authenticate_card(pin: str) -> tuple[str, str]:
    """
    Verifierar PIN mot smartkortet.
    Returnerar (cert_pem, upn) eller kastar ValueError.
    """
    lib = pkcs11.lib(PKCS11_LIB)

    # Hitta första token med kort
    try:
        token = next(
            slot.get_token()
            for slot in lib.get_slots(token_present=True)
        )
    except StopIteration:
        raise ValueError("Inget smartkort hittades")

    # Öppna session och verifiera PIN
    try:
        sess = token.open(user_pin=pin, rw=False)
    except pkcs11.exceptions.PinIncorrect:
        raise ValueError("Fel PIN-kod")
    except pkcs11.exceptions.PinLocked:
        raise ValueError("PIN-koden är låst – kontakta IT")

    try:
        # Hämta certifikat från kortet
        certs = list(sess.get_objects({
            pkcs11.Attribute.CLASS: pkcs11.ObjectClass.CERTIFICATE,
        }))
        if not certs:
            raise ValueError("Inget certifikat på kortet")

        cert_der = bytes(certs[0][pkcs11.Attribute.VALUE])
        cert_pem = subprocess.run(
            ["openssl", "x509", "-inform", "DER"],
            input=cert_der, capture_output=True, check=True,
        ).stdout.decode()

        upn = _extract_upn(cert_pem)
        check_revocation(cert_pem)
        log.info(f"Inloggad: {upn}")
        return cert_pem, upn

    finally:
        sess.close()


def decrypt_job(encrypted_data: bytes, cert_pem: str, pin: str) -> bytes:
    """
    Dekrypterar CMS-envelopad jobbdata med smartkortets privata nyckel.
    PIN skickas via en temporär fil – visas ej i processlistan.
    Använder pkcs11-provider (OpenSSL 3.x) i stället för det utgångna pkcs11-engine.
    """
    # Krypterad data och certifikat behöver ligga på disk (openssl cms kräver det).
    # PIN skickas via en FIFO (named pipe) – berör aldrig disk, bara kernelns RAM-buffert.
    # Dekrypterad output skickas till stdout – berör aldrig disk.
    with tempfile.TemporaryDirectory(prefix="secprint_") as tmp:
        tmp_path  = Path(tmp)
        enc_file  = tmp_path / "job.cms"
        cert_file = tmp_path / "user.pem"
        pin_pipe  = tmp_path / "pin.fifo"

        enc_file.write_bytes(encrypted_data)
        cert_file.write_text(cert_pem)
        os.mkfifo(pin_pipe, mode=0o600)

        # Skriv PIN i en tråd – open() på FIFO blockerar tills openssl läser
        def _write_pin() -> None:
            with open(pin_pipe, "w") as fh:
                fh.write(pin)

        pin_thread = threading.Thread(target=_write_pin, daemon=True)
        pin_thread.start()

        result = subprocess.run(
            [
                "openssl", "cms", "-decrypt",
                "-binary",
                "-in",    str(enc_file),
                "-recip", str(cert_file),
                "-inkey", f"pkcs11:type=private;pin-source=file:{pin_pipe}",
                "-provider", "pkcs11",
                "-provider", "default",
                "-out",   "/dev/stdout",
            ],
            check=True,
            capture_output=True,
        )

        pin_thread.join(timeout=5)
        return result.stdout


# ---------------------------------------------------------------------------
# Revokationskontroll (OCSP/CRL)
# ---------------------------------------------------------------------------

def _fetch_url(url: str) -> bytes:
    """Hämtar URL med User-Agent och timeout."""
    req = urllib.request.Request(url, headers={"User-Agent": "SecurePrint/1.0"})
    with urllib.request.urlopen(req, timeout=REVOCATION_TIMEOUT) as resp:
        return resp.read()


def _get_aia_url(cert, oid) -> str:
    """Returnerar URL av given typ ur certifikatets AIA-extension, eller None."""
    try:
        aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess)
        for desc in aia.value:
            if desc.access_method == oid:
                return desc.access_location.value
    except x509.ExtensionNotFound:
        pass
    return None


def _check_ocsp(cert_pem: str, cert) -> None:
    """OCSP-kontroll via openssl. Laddar ner utfärdarens certifikat från AIA."""
    ocsp_url = _get_aia_url(cert, x509.AuthorityInformationAccessOID.OCSP)
    if not ocsp_url:
        raise ValueError("Ingen OCSP-URL i certifikatets AIA-extension")

    issuer_url = _get_aia_url(cert, x509.AuthorityInformationAccessOID.CA_ISSUERS)

    with tempfile.TemporaryDirectory(prefix="secprint_ocsp_") as tmp:
        tmp_path    = Path(tmp)
        cert_file   = tmp_path / "user.pem"
        issuer_file = tmp_path / "issuer.pem"
        cert_file.write_text(cert_pem)

        # Hämta utfärdarens certifikat (behövs för att bygga OCSP-förfrågan)
        if issuer_url:
            try:
                issuer_data = _fetch_url(issuer_url)
                # Konvertera DER → PEM vid behov
                if not issuer_data.startswith(b"-----"):
                    issuer_data = subprocess.run(
                        ["openssl", "x509", "-inform", "DER"],
                        input=issuer_data, capture_output=True, check=True,
                    ).stdout
                issuer_file.write_bytes(issuer_data)
            except Exception as exc:
                log.warning(f"REVOCATION: Kunde inte hämta utfärdarens cert från {issuer_url}: {exc}")

        cmd = [
            "openssl", "ocsp",
            "-cert",    str(cert_file),
            "-url",     ocsp_url,
            "-timeout", str(REVOCATION_TIMEOUT),
            "-CAfile",  REVOCATION_CA_FILE,
        ]
        if issuer_file.exists():
            cmd += ["-issuer", str(issuer_file)]
        else:
            # Utan utfärdarens cert går det inte att verifiera OCSP-signatur
            cmd += ["-noverify"]
            log.warning("REVOCATION: OCSP utan utfärdarens certifikat – responssignatur verifieras ej")

        result = subprocess.run(cmd, capture_output=True, timeout=REVOCATION_TIMEOUT + 5)
        output = (result.stdout + result.stderr).decode(errors="replace")
        log.debug(f"REVOCATION: openssl ocsp output: {output[:400]!r}")

        if ": good" in output:
            log.info(f"REVOCATION: OCSP OK  serial={cert.serial_number:X}")
        elif ": revoked" in output:
            raise ValueError("Certifikatet är återkallat")
        else:
            raise ValueError(f"OCSP-svar otolkat: {output[:150].strip()!r}")


def _check_crl(cert) -> None:
    """CRL-kontroll via cryptography-biblioteket."""
    try:
        cdp = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints)
    except x509.ExtensionNotFound:
        raise ValueError("Ingen CRL-distributionspunkt i certifikatet")

    last_exc = ValueError("Inga nåbara CRL-distributionspunkter")
    for dp in cdp.value:
        for gn in dp.full_name or []:
            if not isinstance(gn, x509.UniformResourceIdentifier):
                continue
            crl_url = gn.value
            if not crl_url.startswith("http"):
                continue
            try:
                crl_data = _fetch_url(crl_url)
                crl = load_der_x509_crl(crl_data)
                rev = crl.get_revoked_certificate_by_serial_number(cert.serial_number)
                if rev:
                    raise ValueError("Certifikatet är återkallat (CRL)")
                log.info(f"REVOCATION: CRL OK  serial={cert.serial_number:X}")
                return
            except ValueError:
                raise
            except Exception as exc:
                last_exc = exc
                log.warning(f"REVOCATION: CRL {crl_url} misslyckades: {exc}")
    raise last_exc


def check_revocation(cert_pem: str) -> None:
    """
    Kontrollerar att certifikatet inte är återkallat (OCSP → CRL-fallback).

    REVOCATION_CHECK=ocsp    – OCSP med CRL-fallback; mjukt fel vid nätverksproblem
    REVOCATION_CHECK=strict  – som ocsp, men hårt fel om status ej kan fastställas
    REVOCATION_CHECK=none    – inaktivt (inte rekommenderat i produktion)
    """
    if REVOCATION_CHECK == "none":
        log.warning("REVOCATION: Revokationskontroll inaktiverad (REVOCATION_CHECK=none)")
        return

    cert = x509.load_pem_x509_certificate(cert_pem.encode())

    # Försök OCSP
    try:
        _check_ocsp(cert_pem, cert)
        return
    except ValueError as exc:
        if "återkallat" in str(exc):
            raise                                  # Explicit revokation → propagera alltid
        log.warning(f"REVOCATION: OCSP ej avgörande ({exc}), provar CRL…")
    except Exception as exc:
        log.warning(f"REVOCATION: OCSP-fel ({exc}), provar CRL…")

    # Fallback CRL
    try:
        _check_crl(cert)
        return
    except ValueError as exc:
        if "återkallat" in str(exc):
            raise
        log.warning(f"REVOCATION: CRL ej avgörande: {exc}")
    except Exception as exc:
        log.warning(f"REVOCATION: CRL-fel: {exc}")

    # Varken OCSP eller CRL nåddes
    if REVOCATION_CHECK == "strict":
        raise ValueError("Revokationsstatus kunde inte fastställas (REVOCATION_CHECK=strict)")
    log.warning("REVOCATION: Varken OCSP eller CRL nåddes – inloggning tillåts (mjukt läge)")


# ---------------------------------------------------------------------------
# S3
# ---------------------------------------------------------------------------

def _s3():
    return boto3.client(
        "s3",
        endpoint_url=S3_ENDPOINT,
        aws_access_key_id=S3_ACCESS_KEY,
        aws_secret_access_key=S3_SECRET_KEY,
        config=Config(signature_version="s3v4"),
    )


def download_from_s3(s3_key: str) -> bytes:
    resp = _s3().get_object(Bucket=S3_BUCKET, Key=s3_key)
    return resp["Body"].read()


# ---------------------------------------------------------------------------
# PostgreSQL
# ---------------------------------------------------------------------------

def _db():
    return psycopg2.connect(DATABASE_URL)


def get_pending_jobs(upn: str) -> list[dict]:
    conn = _db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT id, title, copies, options, encrypted_size, submitted_at, expires_at
                FROM   pending_jobs
                WHERE  user_upn = %s
                ORDER  BY submitted_at DESC
                """,
                (upn,),
            )
            return [dict(row) for row in cur.fetchall()]
    finally:
        conn.close()


def mark_retrieved(job_id: str) -> None:
    conn = _db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE print_jobs
                SET    status        = 'retrieved',
                       retrieved_at  = NOW(),
                       retrieved_by  = %s
                WHERE  id = %s
                """,
                (TERMINAL_ID, job_id),
            )
        conn.commit()
    finally:
        conn.close()


def cancel_job_db(job_id: str, upn: str) -> None:
    conn = _db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE print_jobs SET status = 'cancelled' WHERE id = %s AND user_upn = %s",
                (job_id, upn),
            )
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Flask-rutter
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html", terminal_id=TERMINAL_ID, printer=LOCAL_PRINTER)


@app.route("/api/status")
def api_status():
    """Frontendens polling: kortläge + inloggningsstatus."""
    with _card_lock:
        card = _card_present

    authenticated = "upn" in session and card
    if not card:
        session.clear()

    return jsonify({
        "card_present":  card,
        "authenticated": authenticated,
        "upn":           session.get("upn"),
    })


@app.route("/api/login", methods=["POST"])
def api_login():
    """Verifiera PIN, extrahera UPN ur certifikatet."""
    pin = request.json.get("pin", "").strip()
    if not pin or not pin.isdigit() or len(pin) < 4:
        return jsonify({"error": "Ogiltig PIN-kod"}), 400

    try:
        cert_pem, upn = authenticate_card(pin)
        session.permanent    = True
        session["upn"]       = upn
        session["pin_enc"]   = _session_cipher().encrypt(pin.encode()).decode()
        session["cert_pem"]  = cert_pem
        log.info(f"AUDIT login_ok upn={upn} terminal={TERMINAL_ID}")
        return jsonify({"upn": upn})
    except ValueError as exc:
        log.warning(f"AUDIT login_fail terminal={TERMINAL_ID} reason={exc}")
        return jsonify({"error": str(exc)}), 401


@app.route("/api/jobs")
def api_jobs():
    """Lista inloggad användares jobb."""
    if "upn" not in session:
        log.warning(f"AUDIT unauthorized endpoint=jobs terminal={TERMINAL_ID}")
        return jsonify({"error": "Ej inloggad"}), 401

    now  = datetime.now(timezone.utc)
    jobs = get_pending_jobs(session["upn"])
    for job in jobs:
        job["submitted_at"]      = job["submitted_at"].strftime("%d %b %H:%M")
        job["size_kb"]           = round(job["encrypted_size"] / 1024)
        job["id"]                = str(job["id"])
        opts                     = json.loads(job.get("options") or '{}')
        job["options_summary"]   = summarize_options(opts)
        minutes_left             = int((job["expires_at"] - now).total_seconds() / 60)
        job["expires_in_minutes"] = max(0, minutes_left)
        job.pop("options", None)
        job.pop("expires_at", None)
        job.pop("encrypted_size", None)
    return jsonify(jobs)


@app.route("/api/print/<job_id>", methods=["POST"])
def api_print(job_id: str):
    """Hämta, dekryptera och skriv ut ett jobb."""
    if "upn" not in session:
        log.warning(f"AUDIT unauthorized endpoint=print job_id={job_id} terminal={TERMINAL_ID}")
        return jsonify({"error": "Ej inloggad"}), 401

    upn      = session["upn"]
    pin      = _session_cipher().decrypt(session["pin_enc"].encode()).decode()
    cert_pem = session["cert_pem"]

    # Hämta jobbet från PostgreSQL för att verifiera ägarskap + s3_key
    conn = _db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT * FROM pending_jobs WHERE id = %s AND user_upn = %s",
                (job_id, upn),
            )
            job = cur.fetchone()
    finally:
        conn.close()

    if not job:
        return jsonify({"error": "Jobbet finns inte eller tillhör inte dig"}), 404

    try:
        log.info(f"Hämtar {job['s3_key']} för {upn}")
        encrypted = download_from_s3(job["s3_key"])

        log.info(f"Dekrypterar jobb {job_id} för {upn}...")
        decrypted = decrypt_job(encrypted, cert_pem, pin)

        # Skriv till tempfil med rätt ändelse så CUPS kan identifiera formatet
        # och tillämpa rätt filterkedja (t.ex. PDF → raster för bläckstråleskrivare).
        # Att skicka data via stdin utan formatinfo ger skräptecken på skrivaren.
        suffix = _detect_print_suffix(decrypted)
        log.info(f"Skriver ut på {LOCAL_PRINTER}: {len(decrypted)} bytes ({suffix})...")
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tf:
            tf.write(decrypted)
            tmp_path = tf.name
        try:
            cmd = build_lpr_cmd(LOCAL_PRINTER, job["copies"], job.get("options") or "{}")
            cmd.append(tmp_path)
            subprocess.run(cmd, check=True, capture_output=True)
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

        mark_retrieved(job_id)
        log.info(f"AUDIT print_ok upn={upn} job_id={job_id} title={job['title']!r} terminal={TERMINAL_ID}")
        return jsonify({"ok": True, "title": job["title"]})

    except subprocess.CalledProcessError as exc:
        log.error(f"AUDIT print_fail upn={upn} job_id={job_id} terminal={TERMINAL_ID} error={exc.stderr}")
        return jsonify({"error": "Utskriften misslyckades – är skrivaren på?"}), 500
    except Exception as exc:
        log.error(f"AUDIT print_fail upn={upn} job_id={job_id} terminal={TERMINAL_ID} error={exc}", exc_info=True)
        return jsonify({"error": "Oväntat fel – försök igen"}), 500


@app.route("/api/cancel/<job_id>", methods=["POST"])
def api_cancel(job_id: str):
    """Avbryt ett jobb (tas bort från kö men S3-filen rensas av cronjob)."""
    if "upn" not in session:
        log.warning(f"AUDIT unauthorized endpoint=cancel job_id={job_id} terminal={TERMINAL_ID}")
        return jsonify({"error": "Ej inloggad"}), 401
    upn = session["upn"]
    cancel_job_db(job_id, upn)
    log.info(f"AUDIT cancel upn={upn} job_id={job_id} terminal={TERMINAL_ID}")
    return jsonify({"ok": True})


@app.route("/api/logout", methods=["POST"])
def api_logout():
    upn = session.get("upn", "unknown")
    session.clear()
    log.info(f"AUDIT logout upn={upn} terminal={TERMINAL_ID}")
    return jsonify({"ok": True})


# ---------------------------------------------------------------------------
# Start
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    # I produktion (kiosk) lyssnar vi bara på localhost.
    # För container-demo: sätt FLASK_HOST=0.0.0.0
    flask_host = os.environ.get("FLASK_HOST", "127.0.0.1")
    log.info(f"Startar terminal '{TERMINAL_ID}' – skrivare: {LOCAL_PRINTER} – host: {flask_host}")
    app.run(host=flask_host, port=5000, debug=False)
