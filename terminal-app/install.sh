#!/bin/bash
# =============================================================================
# Installationsskript för tunna terminalen (Raspberry Pi / x86 Debian)
# Kör som root: sudo bash install.sh
# =============================================================================
set -euo pipefail

APP_DIR="/opt/secure-print-terminal"
ENV_FILE="/etc/secure-print/terminal.env"
SERVICE="secure-print-terminal"

log()  { echo "▸ $*"; }
ask()  { read -rp "  $1: " "$2"; }

echo "════════════════════════════════════════"
echo "  Secure Print Terminal – Installation"
echo "════════════════════════════════════════"

# ── Systemberoenden ──────────────────────────────────────────
log "Installerar systemberoenden..."
apt-get update -qq
apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv \
    opensc pcscd \
    libengine-pkcs11-openssl \
    cups-client \
    chromium \
    xdotool \
    unclutter          # döljer muspekaren på pekskärm

# Aktivera och starta pcscd (smartkortsdemonen)
systemctl enable --now pcscd

# ── Applikationskatalog ──────────────────────────────────────
log "Skapar applikationskatalog: $APP_DIR"
mkdir -p "$APP_DIR"
cp -r ./* "$APP_DIR/"

# ── Systemanvändare ──────────────────────────────────────────
log "Skapar systemanvändare 'secprint'..."
if ! id -u secprint &>/dev/null; then
    useradd -r -s /sbin/nologin -d "$APP_DIR" secprint
fi
# Behöver vara i pcscd-gruppen för kortåtkomst
usermod -aG pcscd secprint 2>/dev/null || true

# ── Python virtual environment ───────────────────────────────
log "Skapar Python virtual environment..."
python3 -m venv "$APP_DIR/venv"
"$APP_DIR/venv/bin/pip" install --quiet -r "$APP_DIR/requirements.txt"
chown -R secprint:secprint "$APP_DIR"

# ── Konfigurera miljövariabler ───────────────────────────────
log "Konfigurerar miljövariabler..."
mkdir -p /etc/secure-print
chmod 700 /etc/secure-print

if [ ! -f "$ENV_FILE" ]; then
    echo
    echo "Fyll i anslutningsuppgifter:"
    ask "PostgreSQL-URL (postgresql://user:pass@host/db)" DB_URL
    ask "S3-endpoint (https://minio.company.com)"         S3_EP
    ask "S3 access key"                                    S3_AK
    ask "S3 secret key"                                    S3_SK
    ask "S3 bucket"                                        S3_BK
    ask "Lokal skrivarnamn (lpadmin -p namn)"              PRINTER
    ask "Terminal-ID (t.ex. terminal-printer-a)"           TID

    cat > "$ENV_FILE" <<EOF
# Secure Print Terminal – konfiguration
DATABASE_URL=$DB_URL
S3_ENDPOINT=$S3_EP
S3_ACCESS_KEY=$S3_AK
S3_SECRET_KEY=$S3_SK
S3_BUCKET=$S3_BK
LOCAL_PRINTER=$PRINTER
TERMINAL_ID=$TID
PKCS11_LIB=/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so
EOF
    chmod 600 "$ENV_FILE"
    chown secprint:secprint "$ENV_FILE"
    log "Konfiguration sparad: $ENV_FILE"
else
    log "Konfiguration finns redan: $ENV_FILE"
fi

# ── Kiosk-startskript ────────────────────────────────────────
log "Skapar kiosk-startskript..."
cat > /etc/secure-print/kiosk.sh <<'KIOSK'
#!/bin/bash
# Startas av displayhanteraren (LightDM/GDM autostart)

# Dölj muspekare
unclutter -idle 1 &

# Vänta tills Flask svarar
until curl -s http://127.0.0.1:5000 > /dev/null; do sleep 1; done

# Starta Chromium i kiosk-läge
exec chromium \
    --kiosk \
    --noerrdialogs \
    --disable-infobars \
    --disable-session-crashed-bubble \
    --disable-component-update \
    --no-first-run \
    --check-for-update-interval=31536000 \
    http://127.0.0.1:5000
KIOSK
chmod +x /etc/secure-print/kiosk.sh

# Skapa autostart-fil (XFCE/LXDE/Openbox)
mkdir -p /etc/xdg/autostart
cat > /etc/xdg/autostart/secure-print-kiosk.desktop <<'DESKTOP'
[Desktop Entry]
Type=Application
Name=Secure Print Kiosk
Exec=/etc/secure-print/kiosk.sh
X-GNOME-Autostart-enabled=true
DESKTOP

# ── systemd-tjänst ───────────────────────────────────────────
log "Installerar systemd-tjänst..."
cp "$APP_DIR/secure-print-terminal.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now "$SERVICE"

# ── Verifiera ────────────────────────────────────────────────
echo
echo "════════════════════════════════════════"
log "Installation klar!"
echo
echo "  Tjänststatus:  systemctl status $SERVICE"
echo "  Loggar:        journalctl -u $SERVICE -f"
echo "  Konfig:        $ENV_FILE"
echo "════════════════════════════════════════"
