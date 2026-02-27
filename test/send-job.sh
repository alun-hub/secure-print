#!/bin/bash
# =============================================================================
# Skickar ett testutskriftsjobb till den lokala CUPS-containern
#
# Kör setup.sh först. Sedan: bash test/send-job.sh
# =============================================================================
set -euo pipefail

CUPS_HOST="localhost"
CUPS_PORT="631"
QUEUE="s3-queue"
UPN="testuser@company.com"

log() { echo "▸ $*"; }
ok()  { echo "  ✓ $*"; }

# =============================================================================
log "Skapar test-PDF"
# =============================================================================
# Kräver ghostscript (gs) eller enklare: skicka en PostScript-sträng direkt
JOB_FILE="/tmp/secprint-test-$$.ps"

cat > "$JOB_FILE" <<'PS'
%!PS-Adobe-3.0
%%Title: Testutskrift – Secure Print
%%Pages: 1
%%EndComments
%%Page: 1 1

/Helvetica-Bold findfont 28 scalefont setfont
100 700 moveto
(Testutskrift) show

/Helvetica findfont 16 scalefont setfont
100 650 moveto
(Secure Print – end-to-end kryptering) show
100 620 moveto
(Jobb krypterat med användarens X.509-certifikat) show
100 590 moveto
(Dekrypteras med smartkort vid skrivaren) show

/Helvetica findfont 12 scalefont setfont
100 100 moveto
(Genererad: ) show

showpage
%%EOF
PS

ok "PostScript-fil: $JOB_FILE"

# =============================================================================
log "Skickar jobb till CUPS (UPN: $UPN)"
# =============================================================================
# -U sätter job-originating-user-name (ersätter Kerberos i testläge)
# -h pekar mot docker-containerns CUPS-instans
# -T är jobbtiteln

JOB_ID=$(lpr \
    -h "$CUPS_HOST:$CUPS_PORT" \
    -P "$QUEUE" \
    -U "$UPN" \
    -T "Testdokument $(date '+%H:%M:%S')" \
    -# 1 \
    "$JOB_FILE" 2>&1 && lpstat -h "$CUPS_HOST:$CUPS_PORT" -o 2>/dev/null | tail -1 | awk '{print $1}' || echo "okänt")

ok "Jobb skickat"

# =============================================================================
log "Väntar på att backend ska bearbeta jobbet (max 15s)"
# =============================================================================
for i in $(seq 1 15); do
    COUNT=$(psql -qt "postgresql://printuser:printpass@localhost/secure_print" \
        -c "SELECT COUNT(*) FROM print_jobs WHERE user_upn='$UPN' AND status='pending'" \
        2>/dev/null | tr -d ' ')
    if [ "${COUNT:-0}" -gt 0 ]; then
        ok "Jobbet finns i databasen ($COUNT väntande)"
        break
    fi
    sleep 1
done

# =============================================================================
log "Verifiering"
# =============================================================================
echo
echo "── Databas ──────────────────────────────────────────"
psql "postgresql://printuser:printpass@localhost/secure_print" \
    -c "SELECT id, title, encrypted_size, submitted_at, status FROM pending_jobs WHERE user_upn='$UPN' ORDER BY submitted_at DESC LIMIT 3;" \
    2>/dev/null || echo "  (psql ej installerat – kolla i MinIO-konsolen)"

echo
echo "── S3 (krypterade filer) ────────────────────────────"
AWS_ACCESS_KEY_ID=minioadmin \
AWS_SECRET_ACCESS_KEY=minioadmin123 \
aws s3 ls "s3://secure-print-jobs/jobs/$UPN/" \
    --endpoint-url http://localhost:9000 \
    --human-readable \
    --no-sign-request \
    2>/dev/null || echo "  (aws cli ej installerat – kolla http://localhost:9001)"

echo
echo "── CUPS-loggar (senaste 10 rader) ───────────────────"
docker compose logs --tail=10 cups 2>/dev/null || true

# Städa upp
rm -f "$JOB_FILE"

echo
echo "════════════════════════════════════════════════════"
echo "  Jobb skickat!"
echo
echo "  Nästa steg: starta terminalen och hämta utskriften"
echo "    export \$(cat test/terminal.env | xargs)"
echo "    cd terminal-app && python3 app.py"
echo "    Öppna http://localhost:5000"
echo "    PIN: 1234"
echo "════════════════════════════════════════════════════"
