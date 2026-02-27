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

import os
import sys
import subprocess
import tempfile
import threading
import time
import logging
import secrets
from datetime import datetime, timezone
from pathlib import Path

import boto3
import psycopg2
import psycopg2.extras
import pkcs11
import pkcs11.util.rsa
from cryptography import x509
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
PKCS11_LIB      = os.environ.get("PKCS11_LIB", "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so")

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
app.config["PERMANENT_SESSION_LIFETIME"] = 300  # 5 minuter

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
        log.info(f"Inloggad: {upn}")
        return cert_pem, upn

    finally:
        sess.close()


def decrypt_job(encrypted_data: bytes, cert_pem: str, pin: str) -> bytes:
    """
    Dekrypterar CMS-envelopad jobbdata med smartkortets privata nyckel.
    PIN skickas via miljövariabel (PKCS11_PIN) – visas ej i processlistan.
    """
    with tempfile.TemporaryDirectory(prefix="secprint_") as tmp:
        enc_file  = Path(tmp) / "job.cms"
        cert_file = Path(tmp) / "user.pem"
        out_file  = Path(tmp) / "job.dat"

        enc_file.write_bytes(encrypted_data)
        cert_file.write_text(cert_pem)

        env = os.environ.copy()
        env["PKCS11_PIN"] = pin

        subprocess.run(
            [
                "openssl", "cms", "-decrypt",
                "-in",    str(enc_file),
                "-recip", str(cert_file),
                "-inkey", "pkcs11:type=private",
                "-keyform", "engine",
                "-engine", "pkcs11",
                "-out",   str(out_file),
            ],
            env=env,
            check=True,
            capture_output=True,
        )

        return out_file.read_bytes()


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
                SELECT id, title, copies, encrypted_size, submitted_at
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
    return render_template("index.html", terminal_id=TERMINAL_ID)


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
        session["upn"]      = upn
        session["pin"]      = pin
        session["cert_pem"] = cert_pem
        return jsonify({"upn": upn})
    except ValueError as exc:
        log.warning(f"Inloggningsfel: {exc}")
        return jsonify({"error": str(exc)}), 401


@app.route("/api/jobs")
def api_jobs():
    """Lista inloggad användares jobb."""
    if "upn" not in session:
        return jsonify({"error": "Ej inloggad"}), 401

    jobs = get_pending_jobs(session["upn"])
    for job in jobs:
        # Gör datumet läsbart och storleken mänsklig
        job["submitted_at"] = job["submitted_at"].strftime("%d %b %H:%M")
        job["size_kb"]      = round(job["encrypted_size"] / 1024)
        job["id"]           = str(job["id"])
    return jsonify(jobs)


@app.route("/api/print/<job_id>", methods=["POST"])
def api_print(job_id: str):
    """Hämta, dekryptera och skriv ut ett jobb."""
    if "upn" not in session:
        return jsonify({"error": "Ej inloggad"}), 401

    upn      = session["upn"]
    pin      = session["pin"]
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

        log.info("Dekrypterar...")
        decrypted = decrypt_job(encrypted, cert_pem, pin)

        log.info(f"Skriver ut på {LOCAL_PRINTER}...")
        subprocess.run(
            ["lpr", "-P", LOCAL_PRINTER, "-#", str(job["copies"])],
            input=decrypted,
            check=True,
            capture_output=True,
        )

        mark_retrieved(job_id)
        log.info(f"Utskrift klar: {job['title']}")
        return jsonify({"ok": True, "title": job["title"]})

    except subprocess.CalledProcessError as exc:
        log.error(f"Utskriftsfel: {exc.stderr}")
        return jsonify({"error": "Utskriften misslyckades – är skrivaren på?"}), 500
    except Exception as exc:
        log.error(f"Fel: {exc}", exc_info=True)
        return jsonify({"error": "Oväntat fel – försök igen"}), 500


@app.route("/api/cancel/<job_id>", methods=["POST"])
def api_cancel(job_id: str):
    """Avbryt ett jobb (tas bort från kö men S3-filen rensas av cronjob)."""
    if "upn" not in session:
        return jsonify({"error": "Ej inloggad"}), 401
    cancel_job_db(job_id, session["upn"])
    return jsonify({"ok": True})


@app.route("/api/logout", methods=["POST"])
def api_logout():
    session.clear()
    return jsonify({"ok": True})


# ---------------------------------------------------------------------------
# Start
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    log.info(f"Startar terminal '{TERMINAL_ID}' – skrivare: {LOCAL_PRINTER}")
    app.run(host="127.0.0.1", port=5000, debug=False)
