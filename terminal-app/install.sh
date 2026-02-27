#!/bin/bash
# =============================================================================
# Installationsskript för tunna terminalen (Raspberry Pi / x86 Debian)
# Kör som root: sudo bash install.sh
#
# Drivrutinsflöde:
#   Jobbet lagras i S3 som rå PostScript/PDF (avsändarens CUPS kör inga
#   filter för s3print-kön). Vid utskrift anropar terminalen lpr, och det
#   är CUPS *här* som tillämpar drivrutinen och konverterar till skrivarens
#   format. Drivrutinen behövs alltså på terminalen – inte på avsändardatorn.
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
    cups \
    chromium \
    xdotool \
    unclutter          # döljer muspekaren på pekskärm

# Aktivera och starta pcscd (smartkortsdemonen) och CUPS
systemctl enable --now pcscd
systemctl enable --now cups

# ── Applikationskatalog ──────────────────────────────────────
log "Skapar applikationskatalog: $APP_DIR"
mkdir -p "$APP_DIR"
cp -r ./* "$APP_DIR/"

# ── Systemanvändare ──────────────────────────────────────────
log "Skapar systemanvändare 'secprint'..."
if ! id -u secprint &>/dev/null; then
    useradd -r -s /sbin/nologin -d "$APP_DIR" secprint
fi
# Behöver vara i pcscd-gruppen för kortåtkomst och lpadmin-gruppen för utskrift
usermod -aG pcscd secprint   2>/dev/null || true
usermod -aG lpadmin secprint 2>/dev/null || true

# ── Python virtual environment ───────────────────────────────
log "Skapar Python virtual environment..."
python3 -m venv "$APP_DIR/venv"
"$APP_DIR/venv/bin/pip" install --quiet -r "$APP_DIR/requirements.txt"
chown -R secprint:secprint "$APP_DIR"

# ── Detektera PKCS11-bibliotekssökväg ────────────────────────
ARCH=$(dpkg --print-architecture 2>/dev/null || uname -m)
case "$ARCH" in
    amd64|x86_64)  PKCS11_LIB="/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so"  ;;
    arm64|aarch64) PKCS11_LIB="/usr/lib/aarch64-linux-gnu/opensc-pkcs11.so" ;;
    armhf|armv7l)  PKCS11_LIB="/usr/lib/arm-linux-gnueabihf/opensc-pkcs11.so" ;;
    *)             PKCS11_LIB="/usr/lib/opensc-pkcs11.so" ;;
esac
log "Arkitektur: $ARCH → PKCS11_LIB=$PKCS11_LIB"

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
    ask "Terminal-ID (t.ex. terminal-plan3-rum201)"        TID

    # Skrivarkonfigurationen sker i nästa avsnitt – PRINTER_NAME sätts där
    PRINTER_NAME=""
else
    log "Konfiguration finns redan: $ENV_FILE"
    # Läs befintligt skrivarnamn för att ev. konfigurera om
    PRINTER_NAME=$(grep '^LOCAL_PRINTER=' "$ENV_FILE" | cut -d= -f2 || true)
fi

# ── Skrivarkonfiguration ─────────────────────────────────────
#
# Jobbet lagras i S3 som rå PS/PDF. Terminalen tar emot detta och skickar
# det via lpr till CUPS. CUPS tillämpar sedan drivrutinen för att konvertera
# till skrivarens format (PCL, ESC/P, native IPP, etc.).
#
# IPP Everywhere (drivrutinslöst) fungerar med de flesta skrivare tillverkade
# efter 2013. För äldre modeller behövs ett PPD-baserat drivrutinspaket.
#
echo
echo "════════════════════════════════════════"
echo "  Skrivarkonfiguration"
echo "════════════════════════════════════════"
echo
echo "  Tillgängliga URI-format:"
echo "    ipp://192.168.1.10/ipp/print     nätverksskrivare (IPP, rekommenderas)"
echo "    socket://192.168.1.10:9100       nätverksskrivare (raw TCP/9100)"
echo "    lpd://192.168.1.10/queue         LPD/LPR-protokoll"
echo "    usb://Tillverkare/Modell?serial  USB-ansluten"
echo
echo "  Tips: kör 'lpinfo -v' för att lista detekterade skrivare"
echo
ask "Skrivar-URI" PRINTER_URI
ask "Skrivarnamn  (t.ex. HP-LaserJet-M404, visas i terminalen)" PRINTER_NAME

echo
echo "  Drivrutinsval:"
echo "  [1] IPP Everywhere – drivrutinslöst, rekommenderas för skrivare ≥ 2013"
echo "  [2] Generisk PostScript – för PS-kompatibla skrivare utan IPP-stöd"
echo "  [3] HP (hplip) – installerar HP:s drivrutinspaket"
echo "  [4] Gutenprint – installerar Gutenprint (Canon, Epson, m.fl.)"
echo "  [5] PPD-fil – ange sökväg till befintlig .ppd (t.ex. från tillverkaren)"
echo
ask "Val [1-5, Enter = 1]" DRV_CHOICE
DRV_CHOICE="${DRV_CHOICE:-1}"

case "$DRV_CHOICE" in
    1)
        log "Konfigurerar med IPP Everywhere..."
        lpadmin -p "$PRINTER_NAME" -E -v "$PRINTER_URI" -m everywhere
        ;;
    2)
        log "Konfigurerar med generisk PostScript..."
        lpadmin -p "$PRINTER_NAME" -E -v "$PRINTER_URI" \
            -m "drv:///sample.drv/generic.ppd"
        ;;
    3)
        log "Installerar hplip..."
        apt-get install -y --no-install-recommends hplip
        # Hitta PPD för modellen via hp-query, annars IPP Everywhere som fallback
        HP_PPD=$(lpinfo -m 2>/dev/null | grep -i "$(echo "$PRINTER_URI" | grep -oP '(?<=HP/).*?(?=\?)' || true)" | head -1 | awk '{print $1}' || true)
        if [ -n "$HP_PPD" ]; then
            log "Hittade HP-PPD: $HP_PPD"
            lpadmin -p "$PRINTER_NAME" -E -v "$PRINTER_URI" -m "$HP_PPD"
        else
            log "Ingen specifik HP-PPD hittad, använder IPP Everywhere."
            log "Kör 'hp-setup' manuellt för avancerade HP-funktioner (t.ex. dubbelsidig, häftning)."
            lpadmin -p "$PRINTER_NAME" -E -v "$PRINTER_URI" -m everywhere
        fi
        ;;
    4)
        log "Installerar Gutenprint..."
        apt-get install -y --no-install-recommends printer-driver-gutenprint
        echo
        echo "  Gutenprint PPD-filer finns i: /usr/share/ppd/gutenprint/"
        echo "  Sök med: ls /usr/share/ppd/gutenprint/ | grep -i <modell>"
        ask "Sökväg till Gutenprint PPD (Enter = IPP Everywhere)" GUTEN_PPD
        if [ -n "$GUTEN_PPD" ]; then
            lpadmin -p "$PRINTER_NAME" -E -v "$PRINTER_URI" -P "$GUTEN_PPD"
        else
            lpadmin -p "$PRINTER_NAME" -E -v "$PRINTER_URI" -m everywhere
        fi
        ;;
    5)
        ask "Sökväg till PPD-fil" PPD_PATH
        if [ ! -f "$PPD_PATH" ]; then
            echo "  Filen '$PPD_PATH' hittades inte – fortsätter ändå (filen kanske monteras senare)"
        fi
        lpadmin -p "$PRINTER_NAME" -E -v "$PRINTER_URI" -P "$PPD_PATH"
        ;;
    *)
        log "Ogiltigt val, använder IPP Everywhere som standard."
        lpadmin -p "$PRINTER_NAME" -E -v "$PRINTER_URI" -m everywhere
        ;;
esac

# Sätt som systemstandard
lpoptions -d "$PRINTER_NAME"

# Verifiera
echo
if lpstat -p "$PRINTER_NAME" 2>/dev/null | grep -q "enabled"; then
    log "Skrivare '$PRINTER_NAME' konfigurerad och tillgänglig ✓"
else
    echo "  ⚠ Skrivare '$PRINTER_NAME' konfigurerad men svarar inte ännu."
    echo "    Kontrollera URI och att skrivaren är påslagen och nåbar."
fi

# ── Spara miljövariabler (om ny installation) ────────────────
if [ ! -f "$ENV_FILE" ]; then
    cat > "$ENV_FILE" <<EOF
# Secure Print Terminal – konfiguration
DATABASE_URL=$DB_URL
S3_ENDPOINT=$S3_EP
S3_ACCESS_KEY=$S3_AK
S3_SECRET_KEY=$S3_SK
S3_BUCKET=$S3_BK
LOCAL_PRINTER=$PRINTER_NAME
TERMINAL_ID=$TID
PKCS11_LIB=$PKCS11_LIB
EOF
    chmod 600 "$ENV_FILE"
    chown secprint:secprint "$ENV_FILE"
    log "Konfiguration sparad: $ENV_FILE"
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
echo "  Skrivare:      lpstat -p $PRINTER_NAME"
echo "════════════════════════════════════════"
