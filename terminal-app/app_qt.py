#!/usr/bin/env python3
"""
Secure Print Terminal – native PyQt6-applikation

Ersätter Flask + Chromium-kiosken.  Ingen webserver, inga öppna portar.
All kommunikation sker direkt via psycopg2 / boto3 / python-pkcs11.

Flöde:
  1. WaitScreen: väntar på smartkort (CardMonitorThread)
  2. PINScreen: PIN-inmatning via knappsats eller tangentbord
  3. JobsScreen: lista utskriftsjobb, skriv ut eller avbryt
  4. Automatisk utloggning efter 5 min inaktivitet eller när kortet dras ut
"""

import json
import logging
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import boto3
import psycopg2
import psycopg2.extras
import pkcs11
import pkcs11.util.rsa
from botocore.config import Config
from cryptography import x509
from cryptography.x509 import load_der_x509_crl

from PyQt6.QtCore import (
    QEvent, QObject, QThread, QTimer, Qt, pyqtSignal as Signal,
)
from PyQt6.QtWidgets import (
    QApplication, QCheckBox, QFrame, QGridLayout, QHBoxLayout, QLabel,
    QMainWindow, QPushButton, QScrollArea, QStackedWidget, QVBoxLayout,
    QWidget,
)

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
PKCS11_LIB      = os.environ.get(
    "PKCS11_LIB", "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so"
)

# Revokationskontroll: "ocsp" (standard), "strict", "none"
REVOCATION_CHECK   = os.environ.get("REVOCATION_CHECK", "ocsp")
REVOCATION_CA_FILE = os.environ.get(
    "REVOCATION_CA_FILE", "/etc/ssl/certs/ca-certificates.crt"
)
REVOCATION_TIMEOUT = int(os.environ.get("REVOCATION_TIMEOUT", "10"))

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Hjälpfunktioner för utskriftsinställningar
# ---------------------------------------------------------------------------

_SAFE_KEY   = re.compile(r'^[a-zA-Z0-9_\-]+$')
_SAFE_VALUE = re.compile(r'^[a-zA-Z0-9_\-\./: ]+$')


def build_lpr_cmd(printer: str, copies: int, options_json: str) -> list:
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
# Smartkortsövervakning
# ---------------------------------------------------------------------------

def _check_card_present() -> bool:
    """Kontrollerar om ett smartkort är isatt via pkcs11."""
    try:
        lib   = pkcs11.lib(PKCS11_LIB)
        slots = lib.get_slots(token_present=True)
        return len(list(slots)) > 0
    except Exception:
        return False


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


def authenticate_card(pin: str) -> tuple:
    """
    Verifierar PIN mot smartkortet.
    Returnerar (cert_pem, upn) eller kastar ValueError.
    """
    lib = pkcs11.lib(PKCS11_LIB)

    try:
        token = next(
            slot.get_token()
            for slot in lib.get_slots(token_present=True)
        )
    except StopIteration:
        raise ValueError("Inget smartkort hittades")

    try:
        sess = token.open(user_pin=pin, rw=False)
    except pkcs11.exceptions.PinIncorrect:
        raise ValueError("Fel PIN-kod")
    except pkcs11.exceptions.PinLocked:
        raise ValueError("PIN-koden är låst – kontakta IT")

    try:
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
    PIN skickas via en temporär FIFO – berör aldrig disk.
    Använder pkcs11-provider (OpenSSL 3.x).
    """
    with tempfile.TemporaryDirectory(prefix="secprint_") as tmp:
        tmp_path  = Path(tmp)
        enc_file  = tmp_path / "job.cms"
        cert_file = tmp_path / "user.pem"
        pin_pipe  = tmp_path / "pin.fifo"

        enc_file.write_bytes(encrypted_data)
        cert_file.write_text(cert_pem)
        os.mkfifo(pin_pipe, mode=0o600)

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
    req = urllib.request.Request(url, headers={"User-Agent": "SecurePrint/1.0"})
    with urllib.request.urlopen(req, timeout=REVOCATION_TIMEOUT) as resp:
        return resp.read()


def _get_aia_url(cert, oid) -> str:
    try:
        aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess)
        for desc in aia.value:
            if desc.access_method == oid:
                return desc.access_location.value
    except x509.ExtensionNotFound:
        pass
    return None


def _check_ocsp(cert_pem: str, cert) -> None:
    ocsp_url = _get_aia_url(cert, x509.AuthorityInformationAccessOID.OCSP)
    if not ocsp_url:
        raise ValueError("Ingen OCSP-URL i certifikatets AIA-extension")

    issuer_url = _get_aia_url(cert, x509.AuthorityInformationAccessOID.CA_ISSUERS)

    with tempfile.TemporaryDirectory(prefix="secprint_ocsp_") as tmp:
        tmp_path    = Path(tmp)
        cert_file   = tmp_path / "user.pem"
        issuer_file = tmp_path / "issuer.pem"
        cert_file.write_text(cert_pem)

        if issuer_url:
            try:
                issuer_data = _fetch_url(issuer_url)
                if not issuer_data.startswith(b"-----"):
                    issuer_data = subprocess.run(
                        ["openssl", "x509", "-inform", "DER"],
                        input=issuer_data, capture_output=True, check=True,
                    ).stdout
                issuer_file.write_bytes(issuer_data)
            except Exception as exc:
                log.warning(f"REVOCATION: Kunde inte hämta utfärdarens cert: {exc}")

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
    if REVOCATION_CHECK == "none":
        log.warning("REVOCATION: Revokationskontroll inaktiverad (REVOCATION_CHECK=none)")
        return

    cert = x509.load_pem_x509_certificate(cert_pem.encode())

    try:
        _check_ocsp(cert_pem, cert)
        return
    except ValueError as exc:
        if "återkallat" in str(exc):
            raise
        log.warning(f"REVOCATION: OCSP ej avgörande ({exc}), provar CRL…")
    except Exception as exc:
        log.warning(f"REVOCATION: OCSP-fel ({exc}), provar CRL…")

    try:
        _check_crl(cert)
        return
    except ValueError as exc:
        if "återkallat" in str(exc):
            raise
        log.warning(f"REVOCATION: CRL ej avgörande: {exc}")
    except Exception as exc:
        log.warning(f"REVOCATION: CRL-fel: {exc}")

    if REVOCATION_CHECK == "strict":
        raise ValueError("Revokationsstatus kunde inte fastställas (REVOCATION_CHECK=strict)")
    log.warning("REVOCATION: Varken OCSP eller CRL nåddes – inloggning tillåts (mjukt läge)")


# ---------------------------------------------------------------------------
# S3 + PostgreSQL
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


def _db():
    return psycopg2.connect(DATABASE_URL)


def get_pending_jobs(upn: str) -> list:
    conn = _db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT id, title, copies, options, encrypted_size, submitted_at, expires_at, s3_key
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
# QThread-arbetare
# ---------------------------------------------------------------------------

class CardMonitorThread(QThread):
    card_inserted = Signal()
    card_removed  = Signal()

    def run(self):
        present = False
        while True:
            current = _check_card_present()
            if current and not present:
                log.info("Smartkort isatt")
                self.card_inserted.emit()
            elif not current and present:
                log.info("Smartkort borttaget")
                self.card_removed.emit()
            present = current
            time.sleep(1)


class LoginWorker(QThread):
    success = Signal(str, str)   # (upn, cert_pem)
    failure = Signal(str)        # felmeddelande

    def __init__(self, pin: str):
        super().__init__()
        self._pin = pin

    def run(self):
        try:
            cert_pem, upn = authenticate_card(self._pin)
            self.success.emit(upn, cert_pem)
        except ValueError as exc:
            log.warning(f"AUDIT login_fail terminal={TERMINAL_ID} reason={exc}")
            self.failure.emit(str(exc))
        except Exception as exc:
            log.error(f"AUDIT login_fail terminal={TERMINAL_ID} reason={exc}", exc_info=True)
            self.failure.emit("Oväntat fel – försök igen")


class JobLoaderWorker(QThread):
    done  = Signal(list)
    error = Signal(str)

    def __init__(self, upn: str):
        super().__init__()
        self._upn = upn

    def run(self):
        try:
            jobs = get_pending_jobs(self._upn)
            now = datetime.now(timezone.utc)
            for job in jobs:
                job["submitted_at"]       = job["submitted_at"].strftime("%d %b %H:%M")
                job["size_kb"]            = round(job["encrypted_size"] / 1024)
                job["id"]                 = str(job["id"])
                opts                      = json.loads(job.get("options") or '{}')
                job["options_summary"]    = summarize_options(opts)
                minutes_left              = int((job["expires_at"] - now).total_seconds() / 60)
                job["expires_in_minutes"] = max(0, minutes_left)
                job.pop("options", None)
                job.pop("expires_at", None)
                job.pop("encrypted_size", None)
            self.done.emit(jobs)
        except Exception as exc:
            log.error(f"Fel vid hämtning av jobb: {exc}", exc_info=True)
            self.error.emit(str(exc))


class PrintWorker(QThread):
    success = Signal(str)   # job title
    failure = Signal(str)

    def __init__(self, job: dict, cert_pem: str, pin: str):
        super().__init__()
        self._job      = job
        self._cert_pem = cert_pem
        self._pin      = pin

    def run(self):
        job = self._job
        try:
            log.info(f"Hämtar {job['s3_key']} för utskrift...")
            encrypted = download_from_s3(job["s3_key"])

            log.info(f"Dekrypterar jobb {job['id']}...")
            decrypted = decrypt_job(encrypted, self._cert_pem, self._pin)

            suffix = _detect_print_suffix(decrypted)
            log.info(f"Skriver ut på {LOCAL_PRINTER}: {len(decrypted)} bytes ({suffix})")
            with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tf:
                tf.write(decrypted)
                tmp_path = tf.name
            try:
                cmd = build_lpr_cmd(
                    LOCAL_PRINTER,
                    job.get("copies", 1),
                    job.get("options") or "{}",
                )
                cmd.append(tmp_path)
                subprocess.run(cmd, check=True, capture_output=True)
            finally:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

            mark_retrieved(job["id"])
            log.info(f"AUDIT print_ok job_id={job['id']} title={job['title']!r} terminal={TERMINAL_ID}")
            self.success.emit(job["title"])

        except subprocess.CalledProcessError as exc:
            log.error(f"AUDIT print_fail job_id={job['id']} terminal={TERMINAL_ID} stderr={exc.stderr}")
            self.failure.emit("Utskriften misslyckades – är skrivaren på?")
        except Exception as exc:
            log.error(f"AUDIT print_fail job_id={job['id']} terminal={TERMINAL_ID} error={exc}", exc_info=True)
            self.failure.emit("Oväntat fel – försök igen")


class CancelWorker(QThread):
    done = Signal(str)   # job_id

    def __init__(self, job_id: str, upn: str):
        super().__init__()
        self._job_id = job_id
        self._upn    = upn

    def run(self):
        try:
            cancel_job_db(self._job_id, self._upn)
            log.info(f"AUDIT cancel job_id={self._job_id} upn={self._upn} terminal={TERMINAL_ID}")
        except Exception as exc:
            log.error(f"Fel vid avbrytande av jobb {self._job_id}: {exc}", exc_info=True)
        self.done.emit(self._job_id)


# ---------------------------------------------------------------------------
# Aktivitetsfilter för inaktivitetstimer
# ---------------------------------------------------------------------------

class ActivityFilter(QObject):
    activity = Signal()

    def eventFilter(self, obj, event):
        if event.type() in (
            QEvent.Type.MouseMove,
            QEvent.Type.KeyPress,
            QEvent.Type.MouseButtonPress,
            QEvent.Type.TouchBegin,
        ):
            self.activity.emit()
        return False


# ---------------------------------------------------------------------------
# Stylesheet
# ---------------------------------------------------------------------------

STYLESHEET = """
QMainWindow, QWidget {
    background: #1a1a2e;
    color: #e0e0e0;
    font-size: 18pt;
}
QPushButton {
    min-height: 56px;
    min-width: 56px;
    border-radius: 8px;
    background: #2d2d44;
    color: #e0e0e0;
    padding: 8px 16px;
    border: none;
}
QPushButton:pressed {
    background: #3d3d5c;
}
QPushButton[class="primary"] {
    background: #4a90d9;
    color: white;
    font-weight: bold;
}
QPushButton[class="primary"]:pressed {
    background: #3a80c9;
}
QPushButton[class="danger"] {
    background: transparent;
    border: 1px solid #888;
}
QPushButton[class="danger"]:pressed {
    background: #3d2020;
}
QLabel#title {
    font-size: 22pt;
    font-weight: bold;
}
QLabel#error {
    color: #ff6b6b;
}
QCheckBox {
    background: transparent;
    spacing: 8px;
}
QCheckBox::indicator {
    width: 28px;
    height: 28px;
    border-radius: 4px;
    border: 2px solid #666;
    background: #1a1a2e;
}
QCheckBox::indicator:checked {
    background: #4a90d9;
    border-color: #4a90d9;
}
QScrollArea {
    border: none;
}
QScrollBar:vertical {
    background: #1a1a2e;
    width: 8px;
}
QScrollBar::handle:vertical {
    background: #4a4a6a;
    border-radius: 4px;
}
"""


# ---------------------------------------------------------------------------
# Skärmar
# ---------------------------------------------------------------------------

class WaitScreen(QWidget):
    """Väntar på att användaren sätter i ett smartkort."""

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(32)

        icon = QLabel("💳")
        icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon.setStyleSheet("font-size: 96pt; background: transparent;")
        layout.addWidget(icon)

        msg = QLabel("Sätt i smartkort")
        msg.setObjectName("title")
        msg.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(msg)

        sub = QLabel(f"Terminal: {TERMINAL_ID}  |  Skrivare: {LOCAL_PRINTER}")
        sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sub.setStyleSheet("color: #888; font-size: 14pt; background: transparent;")
        layout.addWidget(sub)


class PINScreen(QWidget):
    """PIN-inmatning med numerisk knappsats."""

    login_requested = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._digits = ""

        outer = QVBoxLayout(self)
        outer.setAlignment(Qt.AlignmentFlag.AlignCenter)
        outer.setSpacing(24)

        title = QLabel("Ange PIN-kod")
        title.setObjectName("title")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        outer.addWidget(title)

        self._dots = QLabel("")
        self._dots.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._dots.setStyleSheet("font-size: 28pt; letter-spacing: 12px; background: transparent;")
        outer.addWidget(self._dots)

        # 3x4 knappsats
        grid_widget = QWidget()
        grid = QGridLayout(grid_widget)
        grid.setSpacing(12)
        keys = [
            ("1", 0, 0), ("2", 0, 1), ("3", 0, 2),
            ("4", 1, 0), ("5", 1, 1), ("6", 1, 2),
            ("7", 2, 0), ("8", 2, 1), ("9", 2, 2),
            ("\u232b", 3, 0), ("0", 3, 1), ("OK", 3, 2),
        ]
        for label, row, col in keys:
            btn = QPushButton(label)
            btn.setFixedSize(96, 80)
            if label == "OK":
                btn.setProperty("class", "primary")
                btn.style().unpolish(btn)
                btn.style().polish(btn)
            elif label == "\u232b":
                btn.setProperty("class", "danger")
                btn.style().unpolish(btn)
                btn.style().polish(btn)
            btn.clicked.connect(lambda checked, lbl=label: self._on_key(lbl))
            grid.addWidget(btn, row, col)
        outer.addWidget(grid_widget, alignment=Qt.AlignmentFlag.AlignCenter)

        self._error_label = QLabel("")
        self._error_label.setObjectName("error")
        self._error_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._error_label.setWordWrap(True)
        outer.addWidget(self._error_label)

    def reset(self):
        self._digits = ""
        self._update_dots()
        self._error_label.setText("")

    def show_error(self, msg: str):
        self._error_label.setText(msg)
        self._digits = ""
        self._update_dots()

    def _update_dots(self):
        self._dots.setText("\u25cf " * len(self._digits))

    def _on_key(self, label: str):
        if label == "\u232b":
            self._digits = self._digits[:-1]
            self._update_dots()
        elif label == "OK":
            if len(self._digits) >= 4:
                self._error_label.setText("")
                self.login_requested.emit(self._digits)
        elif label.isdigit():
            if len(self._digits) < 12:
                self._digits += label
                self._update_dots()

    def keyPressEvent(self, event):
        key = event.key()
        if Qt.Key.Key_0 <= key <= Qt.Key.Key_9:
            self._on_key(str(key - Qt.Key.Key_0))
        elif key in (Qt.Key.Key_Backspace, Qt.Key.Key_Delete):
            self._on_key("\u232b")
        elif key in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
            self._on_key("OK")
        else:
            super().keyPressEvent(event)


class JobCard(QFrame):
    """Kort som visar ett enskilt utskriftsjobb."""

    print_requested   = Signal(dict)
    cancel_requested  = Signal(str)
    selection_changed = Signal(str, bool)   # (job_id, selected)

    def __init__(self, job: dict, parent=None):
        super().__init__(parent)
        self._job = job
        self.setFrameShape(QFrame.Shape.StyledPanel)
        self.setStyleSheet(
            "QFrame { background: #2d2d44; border-radius: 8px; padding: 4px; }"
        )

        outer = QHBoxLayout(self)
        outer.setSpacing(12)

        self._checkbox = QCheckBox()
        self._checkbox.toggled.connect(
            lambda checked: self.selection_changed.emit(str(job["id"]), checked)
        )
        outer.addWidget(self._checkbox, alignment=Qt.AlignmentFlag.AlignVCenter)

        content = QVBoxLayout()
        content.setSpacing(8)

        title = QLabel(job["title"])
        title.setStyleSheet("font-weight: bold; font-size: 18pt; background: transparent;")
        title.setWordWrap(True)
        content.addWidget(title)

        parts = []
        if job.get("copies", 1) > 1:
            parts.append(f"{job['copies']} kopior")
        if job.get("options_summary"):
            parts.append(job["options_summary"])
        parts.append(f"{job.get('size_kb', 0)} KB")
        parts.append(job.get("submitted_at", ""))
        meta = QLabel("  \u00b7  ".join(parts))
        meta.setStyleSheet("color: #aaa; font-size: 14pt; background: transparent;")
        meta.setWordWrap(True)
        content.addWidget(meta)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(12)

        print_btn = QPushButton("Skriv ut")
        print_btn.setProperty("class", "primary")
        print_btn.style().unpolish(print_btn)
        print_btn.style().polish(print_btn)
        print_btn.clicked.connect(lambda: self.print_requested.emit(self._job))
        btn_row.addWidget(print_btn)

        cancel_btn = QPushButton("Avbryt")
        cancel_btn.setProperty("class", "danger")
        cancel_btn.style().unpolish(cancel_btn)
        cancel_btn.style().polish(cancel_btn)
        cancel_btn.clicked.connect(lambda: self.cancel_requested.emit(str(job["id"])))
        btn_row.addWidget(cancel_btn)

        btn_row.addStretch()
        content.addLayout(btn_row)
        outer.addLayout(content)

    def is_selected(self) -> bool:
        return self._checkbox.isChecked()

    def set_selected(self, val: bool):
        self._checkbox.setChecked(val)


class JobsScreen(QWidget):
    """Visar lista med utskriftsjobb för inloggad användare."""

    print_job_requested   = Signal(dict)
    cancel_job_requested  = Signal(str)
    bulk_print_requested  = Signal(list)   # list[dict]
    bulk_cancel_requested = Signal(list)   # list[str]  (job_ids)
    logout_requested      = Signal()
    refresh_requested     = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._upn       = ""
        self._workers   = []
        self._selected  = set()     # job_ids (str) som är markerade
        self._cards     = []        # JobCard-instanser i nuvarande lista
        self._jobs_data = []        # job-dicts för bulk-åtgärder

        outer = QVBoxLayout(self)
        outer.setSpacing(0)
        outer.setContentsMargins(24, 16, 24, 16)

        # ── Header ──────────────────────────────────────────────
        header = QHBoxLayout()
        header.setSpacing(16)

        self._upn_label = QLabel("")
        self._upn_label.setStyleSheet("font-size: 16pt; background: transparent;")
        header.addWidget(self._upn_label)

        self._printer_label = QLabel(f"Skrivare: {LOCAL_PRINTER}")
        self._printer_label.setStyleSheet("font-size: 14pt; color: #aaa; background: transparent;")
        header.addWidget(self._printer_label)

        header.addStretch()

        refresh_btn = QPushButton("Uppdatera")
        refresh_btn.clicked.connect(self.refresh_requested.emit)
        header.addWidget(refresh_btn)

        logout_btn = QPushButton("Logga ut")
        logout_btn.setProperty("class", "danger")
        logout_btn.style().unpolish(logout_btn)
        logout_btn.style().polish(logout_btn)
        logout_btn.clicked.connect(self.logout_requested.emit)
        header.addWidget(logout_btn)

        outer.addLayout(header)

        # ── Bulk-åtgärdsrad (visas när jobb finns) ──────────────
        action_bar = QHBoxLayout()
        action_bar.setSpacing(12)

        self._select_all_btn = QPushButton("Markera alla")
        self._select_all_btn.clicked.connect(self._toggle_select_all)
        self._select_all_btn.setVisible(False)
        action_bar.addWidget(self._select_all_btn)

        self._bulk_print_btn = QPushButton("Skriv ut valda (0)")
        self._bulk_print_btn.setProperty("class", "primary")
        self._bulk_print_btn.style().unpolish(self._bulk_print_btn)
        self._bulk_print_btn.style().polish(self._bulk_print_btn)
        self._bulk_print_btn.setVisible(False)
        self._bulk_print_btn.clicked.connect(self._on_bulk_print)
        action_bar.addWidget(self._bulk_print_btn)

        self._bulk_cancel_btn = QPushButton("Ta bort valda (0)")
        self._bulk_cancel_btn.setProperty("class", "danger")
        self._bulk_cancel_btn.style().unpolish(self._bulk_cancel_btn)
        self._bulk_cancel_btn.style().polish(self._bulk_cancel_btn)
        self._bulk_cancel_btn.setVisible(False)
        self._bulk_cancel_btn.clicked.connect(self._on_bulk_cancel)
        action_bar.addWidget(self._bulk_cancel_btn)

        action_bar.addStretch()
        outer.addLayout(action_bar)

        # ── Statusrad ───────────────────────────────────────────
        self._status_label = QLabel("")
        self._status_label.setStyleSheet(
            "color: #aaa; font-size: 14pt; background: transparent; padding: 4px 0;"
        )
        outer.addWidget(self._status_label)

        # ── Scrollyta för jobbkort ──────────────────────────────
        self._scroll = QScrollArea()
        self._scroll.setWidgetResizable(True)
        self._scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        outer.addWidget(self._scroll)

        self._list_widget = QWidget()
        self._list_layout = QVBoxLayout(self._list_widget)
        self._list_layout.setSpacing(12)
        self._list_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        self._scroll.setWidget(self._list_widget)

    def load(self, upn: str):
        self._upn = upn
        self._upn_label.setText(upn)
        self._status_label.setText("Laddar jobb\u2026")
        self._selected.clear()
        self._cards.clear()
        self._jobs_data.clear()
        self._update_bulk_bar()
        self._clear_list()

        worker = JobLoaderWorker(upn)
        worker.done.connect(self._on_jobs_loaded)
        worker.error.connect(self._on_jobs_error)
        self._workers.append(worker)
        worker.start()

    def _clear_list(self):
        while self._list_layout.count():
            item = self._list_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

    def _on_jobs_loaded(self, jobs: list):
        self._status_label.setText("")
        self._selected.clear()
        self._cards.clear()
        self._jobs_data = jobs
        self._clear_list()

        if not jobs:
            self._select_all_btn.setVisible(False)
            empty = QLabel("Inga utskrifter i kö")
            empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
            empty.setStyleSheet(
                "color: #888; font-size: 18pt; background: transparent; padding: 32px;"
            )
            self._list_layout.addWidget(empty)
        else:
            self._select_all_btn.setVisible(True)
            self._select_all_btn.setText("Markera alla")
            for job in jobs:
                card = JobCard(job)
                card.print_requested.connect(self.print_job_requested.emit)
                card.cancel_requested.connect(self.cancel_job_requested.emit)
                card.selection_changed.connect(self._on_selection_changed)
                self._cards.append(card)
                self._list_layout.addWidget(card)

        self._update_bulk_bar()

    def _on_jobs_error(self, msg: str):
        self._status_label.setText(f"Fel: {msg}")
        self._clear_list()
        self._select_all_btn.setVisible(False)
        self._update_bulk_bar()

    def _on_selection_changed(self, job_id: str, selected: bool):
        if selected:
            self._selected.add(job_id)
        else:
            self._selected.discard(job_id)
        self._update_bulk_bar()
        # Uppdatera "Markera alla"-knappens text
        if self._jobs_data:
            all_sel = len(self._selected) == len(self._jobs_data)
            self._select_all_btn.setText("Avmarkera alla" if all_sel else "Markera alla")

    def _toggle_select_all(self):
        all_selected = len(self._selected) == len(self._jobs_data)
        new_state = not all_selected
        for card in self._cards:
            card.set_selected(new_state)
        # selection_changed-signalerna uppdaterar self._selected automatiskt

    def _update_bulk_bar(self):
        n = len(self._selected)
        self._bulk_print_btn.setVisible(n > 0)
        self._bulk_cancel_btn.setVisible(n > 0)
        self._bulk_print_btn.setText(f"Skriv ut valda ({n})")
        self._bulk_cancel_btn.setText(f"Ta bort valda ({n})")

    def _on_bulk_print(self):
        jobs = [j for j in self._jobs_data if str(j["id"]) in self._selected]
        if jobs:
            self.bulk_print_requested.emit(jobs)

    def _on_bulk_cancel(self):
        job_ids = list(self._selected)
        if job_ids:
            self.bulk_cancel_requested.emit(job_ids)


# ---------------------------------------------------------------------------
# Huvudfönster
# ---------------------------------------------------------------------------

class MainWindow(QMainWindow):

    def __init__(self):
        super().__init__()
        # Sessionstillstånd – lagras aldrig på disk
        self._upn      = ""
        self._cert_pem = ""
        self._pin      = ""
        self._workers  = []
        self._card_present = False

        # Skärmar
        self._wait       = WaitScreen()
        self._pin_screen = PINScreen()
        self._jobs       = JobsScreen()

        self._stack = QStackedWidget()
        self._stack.addWidget(self._wait)
        self._stack.addWidget(self._pin_screen)
        self._stack.addWidget(self._jobs)
        self.setCentralWidget(self._stack)

        # Signaler från skärmar
        self._pin_screen.login_requested.connect(self._do_login)
        self._jobs.print_job_requested.connect(self._do_print)
        self._jobs.cancel_job_requested.connect(self._do_cancel)
        self._jobs.bulk_print_requested.connect(self._do_bulk_print)
        self._jobs.bulk_cancel_requested.connect(self._do_bulk_cancel)
        self._jobs.logout_requested.connect(self._logout)
        self._jobs.refresh_requested.connect(self._do_refresh)

        self._pending_bulk = 0

        # Inaktivitetstimer: 5 min
        self._idle_timer = QTimer()
        self._idle_timer.setInterval(300_000)
        self._idle_timer.setSingleShot(True)
        self._idle_timer.timeout.connect(self._logout)

        # Kortövervakning (alltid aktiv)
        self._card_mon = CardMonitorThread()
        self._card_mon.card_inserted.connect(self._on_card_inserted)
        self._card_mon.card_removed.connect(self._on_card_removed)
        self._card_mon.start()

        # Aktivitetsfilter
        self._activity_filter = ActivityFilter()
        self._activity_filter.activity.connect(self._reset_idle_timer)
        QApplication.instance().installEventFilter(self._activity_filter)

        self.showFullScreen()

    def _reset_idle_timer(self):
        if self._idle_timer.isActive():
            self._idle_timer.start()

    def _on_card_inserted(self):
        log.info("Kort isatt – visar PIN-skärm")
        self._card_present = True
        self._pin_screen.reset()
        self._stack.setCurrentWidget(self._pin_screen)
        self._pin_screen.setFocus()

    def _on_card_removed(self):
        log.info("Kort borttaget – loggar ut")
        self._card_present = False
        self._logout()

    def _logout(self):
        log.info(f"AUDIT logout upn={self._upn or 'unknown'} terminal={TERMINAL_ID}")
        self._upn      = ""
        self._cert_pem = ""
        self._pin      = ""
        self._idle_timer.stop()
        if self._card_present:
            # Kortet sitter kvar – visa PIN-skärm direkt för nästa användare
            self._pin_screen.reset()
            self._stack.setCurrentWidget(self._pin_screen)
            self._pin_screen.setFocus()
        else:
            self._stack.setCurrentWidget(self._wait)

    def _do_login(self, pin: str):
        worker = LoginWorker(pin)
        worker.success.connect(self._login_ok)
        worker.failure.connect(self._pin_screen.show_error)
        self._workers.append(worker)
        worker.start()

    def _login_ok(self, upn: str, cert_pem: str):
        log.info(f"AUDIT login_ok upn={upn} terminal={TERMINAL_ID}")
        self._upn      = upn
        self._cert_pem = cert_pem
        sender = self.sender()
        if isinstance(sender, LoginWorker):
            self._pin = sender._pin
        self._idle_timer.start()
        self._stack.setCurrentWidget(self._jobs)
        self._jobs.load(upn)

    def _do_refresh(self):
        if self._upn:
            self._jobs.load(self._upn)

    def _do_print(self, job: dict):
        if not self._upn:
            return
        worker = PrintWorker(job, self._cert_pem, self._pin)
        worker.success.connect(self._on_print_ok)
        worker.failure.connect(self._on_print_fail)
        self._workers.append(worker)
        worker.start()

    def _on_print_ok(self, title: str):
        log.info(f"Utskrift klar: {title!r}")
        if self._upn:
            self._jobs.load(self._upn)

    def _on_print_fail(self, msg: str):
        log.error(f"Utskriftsfel: {msg}")
        self._jobs._status_label.setText(f"Fel: {msg}")

    def _do_cancel(self, job_id: str):
        if not self._upn:
            return
        worker = CancelWorker(job_id, self._upn)
        worker.done.connect(self._on_cancel_done)
        self._workers.append(worker)
        worker.start()

    def _on_cancel_done(self, job_id: str):
        if self._upn:
            self._jobs.load(self._upn)

    def _do_bulk_print(self, jobs: list):
        if not jobs or not self._upn:
            return
        self._pending_bulk += len(jobs)
        for job in jobs:
            worker = PrintWorker(job, self._cert_pem, self._pin)
            worker.success.connect(self._on_bulk_print_done)
            worker.failure.connect(self._on_bulk_print_done)
            self._workers.append(worker)
            worker.start()

    def _on_bulk_print_done(self, _msg: str = ""):
        self._pending_bulk -= 1
        if self._pending_bulk <= 0 and self._upn:
            self._pending_bulk = 0
            self._jobs.load(self._upn)

    def _do_bulk_cancel(self, job_ids: list):
        if not job_ids or not self._upn:
            return
        self._pending_bulk += len(job_ids)
        for job_id in job_ids:
            worker = CancelWorker(job_id, self._upn)
            worker.done.connect(self._on_bulk_cancel_done)
            self._workers.append(worker)
            worker.start()

    def _on_bulk_cancel_done(self, _job_id: str = ""):
        self._pending_bulk -= 1
        if self._pending_bulk <= 0 and self._upn:
            self._pending_bulk = 0
            self._jobs.load(self._upn)


# ---------------------------------------------------------------------------
# Startpunkt
# ---------------------------------------------------------------------------

def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )
    app = QApplication(sys.argv)
    app.setApplicationName("Secure Print Terminal")
    app.setStyleSheet(STYLESHEET)
    win = MainWindow()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
