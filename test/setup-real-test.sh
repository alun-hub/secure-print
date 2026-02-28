#!/bin/bash
# =============================================================================
# Fullständigt E2E-test med riktig YubiKey och nätverksskrivare
#
# Vad skriptet gör:
#   1. Extraherar publik nyckel ur YubiKey slot 9A
#   2. Signerar nytt cert med RSC Root CA (inkl. UPN i SAN)
#   3. Importerar det nya certet till YubiKey slot 9A (rör ej privat nyckel)
#   4. Uppdaterar test/certs.json för CUPS-backendet
#   5. Konfigurerar Epson ET-2810 som lokal CUPS-skrivare
#   6. Startar CUPS-containern i podman
#   7. Skriver terminal.env för att köra terminaltjänsten lokalt
#
# Förutsättningar:
#   - YubiKey isatt (slot 9A har RSA2048-nyckel)
#   - ~/certs/ca.crt och ~/certs/ca.key (RSC Root CA)
#   - podman compose up postgres minio minio-init (körs av skriptet om nödvändigt)
#   - ykman och pkcs11-tool installerade
#
# Kör: bash test/setup-real-test.sh [upn]
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
PKI_DIR="$SCRIPT_DIR/real-pki"

UPN="${1:-alun@company.com}"
PRINTER_IP="192.168.1.128"
PRINTER_NAME="epson-et2810"
CA_CRT="$HOME/certs/ca.crt"
CA_KEY="$HOME/certs/ca.key"
PKCS11_LIB="/usr/lib64/opensc-pkcs11.so"

log()  { echo; echo "▸ $*"; }
ok()   { echo "  ✓ $*"; }
warn() { echo "  ⚠ $*"; }
die()  { echo "  ✗ $*" >&2; exit 1; }

cd "$ROOT_DIR"

# =============================================================================
log "Kontrollerar förutsättningar"
# =============================================================================
[ -f "$CA_CRT" ] || die "CA-certifikat saknas: $CA_CRT"
[ -f "$CA_KEY" ] || die "CA-nyckel saknas: $CA_KEY"
[ -f "$PKCS11_LIB" ] || die "PKCS11-bibliotek saknas: $PKCS11_LIB"
command -v ykman     &>/dev/null || die "ykman saknas (sudo dnf install yubikey-manager)"
command -v pkcs11-tool &>/dev/null || die "pkcs11-tool saknas"
command -v lpadmin   &>/dev/null || die "lpadmin saknas (sudo dnf install cups)"
ok "Alla beroenden finns"

# Kontrollera att YubiKey sitter i
pkcs11-tool --list-slots 2>/dev/null | grep -q "YubiKey\|Yubico" || die "Ingen YubiKey hittad – sätt i kortet"
ok "YubiKey hittad"

mkdir -p "$PKI_DIR"

# =============================================================================
log "Extraherar publik nyckel ur YubiKey slot 9A"
# =============================================================================
pkcs11-tool --read-object --type cert --id 01 2>/dev/null \
    | openssl x509 -inform DER -pubkey -noout \
    > "$PKI_DIR/yubikey-pub.pem"
ok "Publik nyckel: $PKI_DIR/yubikey-pub.pem"

# =============================================================================
log "Signerar nytt certifikat med RSC Root CA (UPN: $UPN)"
# =============================================================================
python3 "$SCRIPT_DIR/issue-yubikey-cert.py" \
    "$PKI_DIR/yubikey-pub.pem" \
    "$CA_CRT" \
    "$CA_KEY" \
    "$UPN" \
    "$PKI_DIR/yubikey-cert.pem" \
    "$SCRIPT_DIR/certs.json"
ok "Nytt cert: $PKI_DIR/yubikey-cert.pem"
ok "certs.json uppdaterad: $SCRIPT_DIR/certs.json"

# =============================================================================
log "Importerar nytt certifikat till YubiKey slot 9A"
# =============================================================================
echo "  OBS: Importerar bara certifikatet – privata nyckeln rörs inte."
echo "  Ange management-nyckel (Enter för standard 010203...08):"
read -r -s MGMT_KEY
MGMT_KEY="${MGMT_KEY:-010203040506070801020304050607080102030405060708}"

if ykman piv certificates import \
    --management-key "$MGMT_KEY" \
    9a "$PKI_DIR/yubikey-cert.pem" 2>&1; then
    ok "Certifikat importerat till YubiKey slot 9A"
else
    warn "Import misslyckades – kontrollera management-nyckeln"
    warn "Du kan importera manuellt: ykman piv certificates import 9a $PKI_DIR/yubikey-cert.pem"
fi

# =============================================================================
log "Verifierar att YubiKey nu innehåller rätt cert"
# =============================================================================
CARD_UPN=$(pkcs11-tool --read-object --type cert --id 01 2>/dev/null \
    | openssl x509 -inform DER -text 2>/dev/null \
    | grep -A1 "Subject Alternative Name" \
    | grep -o "[a-zA-Z0-9._-]*@[a-zA-Z0-9._-]*" | head -1)

if [ "$CARD_UPN" = "$UPN" ]; then
    ok "YubiKey: UPN = $CARD_UPN ✓"
else
    warn "UPN i kortet: '${CARD_UPN:-ej hittad}' (förväntat: $UPN)"
    warn "Fortsätter ändå – terminalen hanterar detta vid inloggning"
fi

# =============================================================================
log "Konfigurerar Epson ET-2810 i lokal CUPS ($PRINTER_IP)"
# =============================================================================
# Kontrollera att lokal CUPS-daemon körs
if ! systemctl --user is-active cups >/dev/null 2>&1 && \
   ! systemctl is-active cups >/dev/null 2>&1; then
    warn "CUPS-daemon verkar inte köra lokalt"
    warn "Starta med: sudo systemctl start cups"
    warn "Skrivarkonfiguration hoppas över"
else
    if ! lpstat -p "$PRINTER_NAME" 2>/dev/null | grep -q "$PRINTER_NAME"; then
        lpadmin \
            -p "$PRINTER_NAME" \
            -v "ipp://$PRINTER_IP/ipp/print" \
            -E \
            -D "Epson ET-2810 (säker utskrift)" \
            2>/dev/null && ok "Skrivare konfigurerad: $PRINTER_NAME → ipp://$PRINTER_IP/ipp/print"
    else
        ok "Skrivaren '$PRINTER_NAME' finns redan"
    fi
fi

# =============================================================================
log "Startar podman-stacken (postgres + minio + cups)"
# =============================================================================
# Kontrollera vad som redan körs
RUNNING=$(podman compose ps 2>/dev/null | grep "Up" | awk '{print $NF}' | tr '\n' ' ')
echo "  Körande: ${RUNNING:-ingen}"

# Starta tjänster som saknas (idempotent)
podman compose up -d postgres minio 2>&1 | grep -v ">>>" | tail -3

echo "  Väntar på postgres och minio..."
for i in $(seq 1 20); do
    PG_OK=$(podman compose ps 2>/dev/null | grep "postgres" | grep -c "healthy" || true)
    MN_OK=$(podman compose ps 2>/dev/null | grep "minio" | grep -q "healthy" && echo 1 || echo 0)
    [ "$PG_OK" -ge 1 ] && [ "$MN_OK" = "1" ] && break
    sleep 3
    [ "$i" -eq 20 ] && die "postgres/minio svarade inte inom 60s"
done
ok "postgres och minio körs"

podman compose up -d minio-init 2>&1 | grep -v ">>>" | tail -2
sleep 3
ok "minio-init klar (bucket secure-print-jobs)"

# Starta CUPS-backendet (behöver certs.json som nu finns)
podman compose up -d cups 2>&1 | grep -v ">>>" | tail -2
echo "  Väntar på CUPS (max 60s)..."
for i in $(seq 1 12); do
    if podman compose exec cups lpstat -r 2>/dev/null | grep -q "scheduler is running"; then
        ok "CUPS-backend igång"
        break
    fi
    sleep 5
    [ "$i" -eq 12 ] && { warn "CUPS svarade inte – kolla: podman compose logs cups"; }
done

# =============================================================================
log "Skriver terminal.env"
# =============================================================================
ENV_FILE="$SCRIPT_DIR/terminal-real.env"
cat > "$ENV_FILE" <<EOF
# Terminalkonfiguration – riktigt E2E-test med YubiKey och Epson ET-2810
# Ladda med: set -a && source test/terminal-real.env && set +a

DATABASE_URL=postgresql://printuser:printpass@localhost/secure_print
S3_ENDPOINT=http://localhost:9000
S3_ACCESS_KEY=minioadmin
S3_SECRET_KEY=minioadmin123
S3_BUCKET=secure-print-jobs
LOCAL_PRINTER=$PRINTER_NAME
TERMINAL_ID=terminal-real-test
PKCS11_LIB=$PKCS11_LIB
REVOCATION_CHECK=none
EOF
ok ".env sparad: $ENV_FILE"

# =============================================================================
echo
echo "════════════════════════════════════════════════════════════"
echo "  E2E-testmiljö klar!"
echo "════════════════════════════════════════════════════════════"
echo
echo "  1. Starta terminal-appen lokalt:"
echo "     set -a && source test/terminal-real.env && set +a"
echo "     cd terminal-app && python3 app.py"
echo "     # Öppna: http://localhost:5000"
echo
echo "  2. Skicka ett testjobb (från en annan terminal):"
echo "     lpr -H localhost:1631 -P s3-queue -U $UPN /etc/os-release"
echo "     # eller:"
echo "     bash test/send-job.sh"
echo
echo "  3. I terminal-UI:t:"
echo "     - Logga in med YubiKey PIN"
echo "     - Välj jobbet → Skriv ut"
echo "     - Utskriften går till Epson ET-2810 ($PRINTER_IP)"
echo
echo "  Loggar:"
echo "     podman compose logs -f cups          # CUPS-backend"
echo "     podman compose logs -f              # allt"
echo "════════════════════════════════════════════════════════════"
