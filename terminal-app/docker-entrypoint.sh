#!/bin/bash
# =============================================================================
# Entrypoint för terminal demo-container
#
# 1. Hittar SoftHSM2-biblioteket
# 2. Genererar test-PKI (CA + användarcert med UPN i SAN)
# 3. Initierar SoftHSM2-token (simulerat smartkort, PIN: 1234)
# 4. Importerar privat nyckel + certifikat till token
# 5. Skapar en demo-lpr som sparar utskrifter till /tmp/prints/
# 6. Väntar på PostgreSQL och MinIO
# 7. Skapar 3 krypterade demojobb (verkligt krypterade, kan skrivas ut)
# 8. Startar Flask på 0.0.0.0:5000
# =============================================================================
set -euo pipefail

log() { echo "▸ [terminal] $*"; }

# ── 1. Hitta SoftHSM2-biblioteket ────────────────────────────────────────────
SOFTHSM2_LIB=""
for path in \
    /usr/lib/softhsm/libsofthsm2.so \
    /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
    /usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so; do
    if [ -f "$path" ]; then
        SOFTHSM2_LIB="$path"
        break
    fi
done
[ -z "$SOFTHSM2_LIB" ] && { echo "ERROR: SoftHSM2-bibliotek hittades inte"; exit 1; }
log "SoftHSM2: $SOFTHSM2_LIB"

# ── 2. Konfigurera SoftHSM2 ──────────────────────────────────────────────────
mkdir -p /app/softhsm2-tokens
cat > /app/softhsm2.conf <<EOF
directories.tokendir = /app/softhsm2-tokens
objectstore.backend = file
log.level = ERROR
EOF
export SOFTHSM2_CONF=/app/softhsm2.conf

# ── 3. Generera test-PKI ─────────────────────────────────────────────────────
log "Genererar test-PKI (CA + användarcert med UPN)..."
python3 /app/gen-cert.py /app/pki

# ── 4. Initiera token och importera nyckel/certifikat ────────────────────────
log "Initierar SoftHSM2-token 'secprint-test' (PIN: 1234)..."
softhsm2-util --init-token \
    --free \
    --label  "secprint-test" \
    --pin    "1234" \
    --so-pin "0000" \
    2>/dev/null

log "Importerar privat nyckel..."
pkcs11-tool --module "$SOFTHSM2_LIB" \
    --token-label "secprint-test" --login --pin "1234" \
    --write-object /app/pki/user.key --type privkey \
    --label "user-key" --id 01 2>/dev/null

log "Importerar certifikat..."
pkcs11-tool --module "$SOFTHSM2_LIB" \
    --token-label "secprint-test" --login --pin "1234" \
    --write-object /app/pki/user.crt --type cert \
    --label "user-cert" --id 01 2>/dev/null

# ── 5. Demo-lpr (sparar utskrifter till /tmp/prints/) ────────────────────────
log "Installerar demo-lpr..."
mkdir -p /tmp/prints
cat > /usr/local/bin/lpr <<'LPREOF'
#!/bin/bash
# Demo-skrivare: tar emot lpr-argument men sparar bara stdin till fil
mkdir -p /tmp/prints
OUTPUT="/tmp/prints/$(date +%Y%m%d_%H%M%S_$$).ps"
cat > "$OUTPUT"
echo "[demo-lpr] Utskrift sparad: $OUTPUT  ($(wc -c < "$OUTPUT") bytes)"
LPREOF
chmod +x /usr/local/bin/lpr

# ── 6. Vänta på PostgreSQL och MinIO ─────────────────────────────────────────
log "Väntar på PostgreSQL..."
until python3 -c "import psycopg2; psycopg2.connect('${DATABASE_URL}')" 2>/dev/null; do
    sleep 2
done
log "PostgreSQL ✓"

log "Väntar på MinIO..."
until curl -sf "${S3_ENDPOINT}/minio/health/live" >/dev/null 2>&1; do
    sleep 2
done
log "MinIO ✓"

# ── 7. Seed: krypterade demojobb i PostgreSQL + MinIO ────────────────────────
log "Skapar demojobb..."
python3 <<'PYEOF'
import os, json, uuid, subprocess, tempfile, boto3, psycopg2
from pathlib import Path
from datetime import datetime, timezone, timedelta
from botocore.config import Config

UPN  = "testuser@company.com"
CERT = Path("/app/pki/user.crt").read_text()

s3 = boto3.client(
    "s3",
    endpoint_url=os.environ["S3_ENDPOINT"],
    aws_access_key_id=os.environ["S3_ACCESS_KEY"],
    aws_secret_access_key=os.environ["S3_SECRET_KEY"],
    config=Config(signature_version="s3v4"),
)
conn = psycopg2.connect(os.environ["DATABASE_URL"])

JOBS = [
    (
        "Årsredovisning 2025.pdf", 2,
        {"sides": "two-sided-long-edge", "media": "iso-a4-210x297mm", "print-color-mode": "monochrome"},
    ),
    (
        "Presentationsbilder Q1.pdf", 1,
        {"sides": "one-sided", "media": "iso-a4-210x297mm", "print-color-mode": "color"},
    ),
    (
        "Faktura_2026-02-15.pdf", 1,
        {"sides": "one-sided", "media": "iso-a4-210x297mm", "print-color-mode": "monochrome"},
    ),
]

# Minimalt PostScript-dokument (verkligt, kan dekrypteras och skrivas ut)
PS = (
    b"%!PS-Adobe-3.0\n"
    b"%%Title: Secure Print Demo\n"
    b"%%Pages: 1\n"
    b"%%EndComments\n"
    b"%%Page: 1 1\n"
    b"/Helvetica findfont 18 scalefont setfont\n"
    b"72 700 moveto (Secure Print Demo) show\n"
    b"showpage\n"
    b"%%EOF\n"
)

with tempfile.NamedTemporaryFile(suffix=".pem", delete=False, mode="w") as f:
    f.write(CERT)
    cert_path = f.name

now = datetime.now(timezone.utc)
for i, (title, copies, opts) in enumerate(JOBS):
    job_id = str(uuid.uuid4())
    s3_key = f"jobs/{UPN}/{job_id}.cms"

    # Kryptera med användarens publika nyckel (samma som app.py gör vid dekryptering)
    with tempfile.TemporaryDirectory() as tmp:
        plain = os.path.join(tmp, "job.ps")
        enc   = os.path.join(tmp, "job.cms")
        Path(plain).write_bytes(PS)
        subprocess.run(
            ["openssl", "cms", "-encrypt", "-binary", "-aes-256-cbc",
             "-in", plain, "-out", enc, "-recip", cert_path],
            check=True, capture_output=True,
        )
        enc_data = Path(enc).read_bytes()

    s3.put_object(
        Bucket=os.environ["S3_BUCKET"],
        Key=s3_key,
        Body=enc_data,
        ContentType="application/cms",
    )

    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO print_jobs
                (id, cups_job_id, user_upn, title, copies, options,
                 s3_key, encrypted_size, submitted_at, expires_at, status)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'pending')
            ON CONFLICT DO NOTHING
            """,
            (
                job_id, 1000 + i, UPN, title, copies, json.dumps(opts),
                s3_key, len(enc_data),
                now - timedelta(minutes=15 * (i + 1)),
                now + timedelta(hours=47),
            ),
        )
    conn.commit()
    print(f"  ✓  {title!r}  ({copies} kopia/or,  {len(enc_data)} bytes)")

conn.close()
os.unlink(cert_path)
PYEOF

# ── 8. Starta Flask ───────────────────────────────────────────────────────────
export PKCS11_LIB="$SOFTHSM2_LIB"
# REVOCATION_CHECK=none: Demomiljön har ingen CA-infrastruktur (OCSP/CRL).
# I produktion ska detta vara "ocsp" (standard) eller "strict".
export REVOCATION_CHECK="none"
export LOCAL_PRINTER="demo-printer"
export TERMINAL_ID="demo-terminal"
export FLASK_HOST="0.0.0.0"

log "════════════════════════════════════════"
log "Terminal UI  →  http://localhost:5000"
log "Logga in med PIN: 1234"
log "Användare: testuser@company.com"
log "════════════════════════════════════════"

exec python3 /app/app.py
