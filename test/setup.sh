#!/bin/bash
# =============================================================================
# Lokal testmiljö – setup
#
# Vad det här skriptet gör:
#   1. Installerar lokala beroenden (python3-cryptography, softhsm2)
#   2. Genererar test-PKI (CA + användarcert med UPN i SAN)
#   3. Sätter upp ett SoftHSM2-token (simulerar smartkort)
#   4. Importerar privat nyckel + certifikat till SoftHSM2
#   5. Startar docker-compose (postgres, minio, cups)
#   6. Sätter upp en lokal CUPS-kö mot filsystem (simulerar skrivare)
#   7. Skriver ut testmiljöns .env-fil för terminalen
#
# Kör: bash test/setup.sh
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
PKI_DIR="$SCRIPT_DIR/pki"
ENV_FILE="$SCRIPT_DIR/terminal.env"

UPN="testuser@company.com"
TOKEN_LABEL="secprint-test"
TOKEN_PIN="1234"
TOKEN_SOPIN="0000"

log()  { echo; echo "▸ $*"; }
ok()   { echo "  ✓ $*"; }
warn() { echo "  ⚠ $*"; }

cd "$ROOT_DIR"

# =============================================================================
log "Kontrollerar beroenden"
# =============================================================================
missing=()
for cmd in python3 openssl softhsm2-util pkcs11-tool docker; do
    if ! command -v "$cmd" &>/dev/null; then
        missing+=("$cmd")
    fi
done

if [ ${#missing[@]} -gt 0 ]; then
    echo "  Saknade kommandon: ${missing[*]}"
    echo "  Installera med:"
    echo "    sudo apt install python3 python3-cryptography openssl softhsm2 opensc docker.io"
    exit 1
fi

# python3-cryptography krävs för gen-cert.py
if ! python3 -c "from cryptography import x509" 2>/dev/null; then
    echo "  Installerar python3-cryptography..."
    pip3 install --quiet cryptography
fi
ok "Alla beroenden finns"

# =============================================================================
log "Genererar test-PKI (CA + användarcertifikat med UPN)"
# =============================================================================
python3 "$SCRIPT_DIR/gen-cert.py" "$PKI_DIR"
ok "Certifikat skapade i $PKI_DIR"

# =============================================================================
log "Konfigurerar SoftHSM2 (simulerat smartkort)"
# =============================================================================
# Konfigurera SoftHSM2 att använda en lokal tokenskatalog
SOFTHSM2_CONF="$SCRIPT_DIR/softhsm2.conf"
SOFTHSM2_TOKENS="$SCRIPT_DIR/softhsm2-tokens"
mkdir -p "$SOFTHSM2_TOKENS"

cat > "$SOFTHSM2_CONF" <<EOF
# SoftHSM2 – lokal testkonfiguration
directories.tokendir = $SOFTHSM2_TOKENS
objectstore.backend = file
log.level = ERROR
EOF

export SOFTHSM2_CONF

# Hitta SoftHSM2-biblioteket
SOFTHSM2_LIB=""
for candidate in \
    /usr/lib/softhsm/libsofthsm2.so \
    /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
    /usr/local/lib/softhsm/libsofthsm2.so; do
    if [ -f "$candidate" ]; then
        SOFTHSM2_LIB="$candidate"
        break
    fi
done
[ -z "$SOFTHSM2_LIB" ] && { echo "SoftHSM2-bibliotek hittades inte"; exit 1; }
ok "SoftHSM2-bibliotek: $SOFTHSM2_LIB"

# Initiera token (ta bort gammalt om det finns)
if softhsm2-util --show-slots 2>/dev/null | grep -q "$TOKEN_LABEL"; then
    warn "Gammalt token '$TOKEN_LABEL' finns – tar bort det"
    rm -rf "$SOFTHSM2_TOKENS"/*
fi

softhsm2-util --init-token \
    --free \
    --label  "$TOKEN_LABEL" \
    --pin    "$TOKEN_PIN" \
    --so-pin "$TOKEN_SOPIN"
ok "SoftHSM2-token '$TOKEN_LABEL' initierat"

# Importera privat nyckel
pkcs11-tool \
    --module  "$SOFTHSM2_LIB" \
    --token-label "$TOKEN_LABEL" \
    --login   --pin "$TOKEN_PIN" \
    --write-object "$PKI_DIR/user.key" \
    --type privkey \
    --label "user-key" \
    --id 01 \
    2>/dev/null
ok "Privat nyckel importerad till SoftHSM2"

# Importera certifikat
pkcs11-tool \
    --module  "$SOFTHSM2_LIB" \
    --token-label "$TOKEN_LABEL" \
    --login   --pin "$TOKEN_PIN" \
    --write-object "$PKI_DIR/user.crt" \
    --type cert \
    --label "user-cert" \
    --id 01 \
    2>/dev/null
ok "Certifikat importerat till SoftHSM2"

# =============================================================================
log "Startar docker-compose (postgres + minio + cups)"
# =============================================================================
# certs.json måste finnas innan CUPS startar (monteras som volym)
[ -f "$SCRIPT_DIR/certs.json" ] || { echo "certs.json saknas – kör gen-cert.py"; exit 1; }

docker compose up -d --build

echo "  Väntar på CUPS (max 60s)..."
for i in $(seq 1 12); do
    if docker compose exec cups lpstat -r 2>/dev/null | grep -q "scheduler is running"; then
        ok "CUPS igång"
        break
    fi
    sleep 5
    if [ "$i" -eq 12 ]; then
        echo "  CUPS svarade inte – kolla: docker compose logs cups"
        exit 1
    fi
done

# =============================================================================
log "Sätter upp lokal CUPS-utskriftskö (skriver till fil)"
# =============================================================================
# Installera CUPS-klient lokalt om det behövs
if ! command -v lpr &>/dev/null; then
    warn "lpr saknas – installera cups-client: sudo apt install cups-client"
fi

# Skapa en lokal kö som pekar mot docker-CUPS
CUPS_SERVER="localhost:631"
if ! lpstat -h "$CUPS_SERVER" -p s3-queue 2>/dev/null | grep -q "s3-queue"; then
    lpadmin \
        -h "$CUPS_SERVER" \
        -p s3-queue \
        -v "ipp://$CUPS_SERVER/printers/s3-queue" \
        -E 2>/dev/null || warn "Kunde inte konfigurera lokal CUPS-klient (OK om du kör send-job.sh direkt)"
fi

# Skapa en simulerad lokal skrivare (skriver till /tmp)
PRINT_OUTPUT="/tmp/secure-print-output"
mkdir -p "$PRINT_OUTPUT"
if ! lpstat -p file-printer 2>/dev/null | grep -q "file-printer"; then
    lpadmin \
        -p file-printer \
        -v "file://$PRINT_OUTPUT/output-%Y%m%d-%H%M%S.ps" \
        -E 2>/dev/null || warn "Kunde inte skapa fil-skrivare (valfri)"
fi
ok "Utskrifter sparas i: $PRINT_OUTPUT"

# =============================================================================
log "Skriver terminal.env (för terminaltestning)"
# =============================================================================
cat > "$ENV_FILE" <<EOF
# Terminalkonfiguration för lokal testmiljö
# Ladda med: export \$(cat test/terminal.env | xargs)

DATABASE_URL=postgresql://printuser:printpass@localhost/secure_print
S3_ENDPOINT=http://localhost:9000
S3_ACCESS_KEY=minioadmin
S3_SECRET_KEY=minioadmin123
S3_BUCKET=secure-print-jobs
LOCAL_PRINTER=file-printer
TERMINAL_ID=terminal-local-test
PKCS11_LIB=$SOFTHSM2_LIB
SOFTHSM2_CONF=$SOFTHSM2_CONF
EOF
ok ".env sparad: $ENV_FILE"

# =============================================================================
echo
echo "════════════════════════════════════════════════════"
echo "  Testmiljö klar!"
echo "════════════════════════════════════════════════════"
echo
echo "  Skicka ett testjobb:"
echo "    bash test/send-job.sh"
echo
echo "  Starta terminalappen:"
echo "    export \$(cat test/terminal.env | xargs)"
echo "    cd terminal-app && python3 app.py"
echo "    # Öppna: http://localhost:5000"
echo
echo "  MinIO-konsol (se lagrade krypterade filer):"
echo "    http://localhost:9001  (minioadmin / minioadmin123)"
echo
echo "  PostgreSQL:"
echo "    psql postgresql://printuser:printpass@localhost/secure_print"
echo "    SELECT * FROM pending_jobs;"
echo
echo "  Stopp:"
echo "    docker compose down"
echo "════════════════════════════════════════════════════"
