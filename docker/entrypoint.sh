#!/bin/bash
# =============================================================================
# Entrypoint för CUPS-container
# Sätter upp TLS, Kerberos och skapar utskriftskön vid första start
# =============================================================================
set -euo pipefail

log() { echo "[entrypoint] $*"; }
err() { echo "[entrypoint] ERROR: $*" >&2; exit 1; }

# -----------------------------------------------------------------------------
# Förbered kataloger
# -----------------------------------------------------------------------------
mkdir -p /etc/cups/ssl /var/spool/cups /var/log/cups /run/cups

# -----------------------------------------------------------------------------
# TLS-certifikat från Kubernetes Secret (monterat under /etc/cups/secrets/)
# I testläge (TEST_MODE=1) genereras ett self-signed cert automatiskt
# -----------------------------------------------------------------------------
if [ -f /etc/cups/secrets/server.crt ]; then
    log "Installerar TLS-certifikat..."
    cp /etc/cups/secrets/server.crt /etc/cups/ssl/server.crt
    cp /etc/cups/secrets/server.key /etc/cups/ssl/server.key
    chmod 640 /etc/cups/ssl/server.key
    chown root:lp /etc/cups/ssl/server.key
elif [ "${TEST_MODE:-0}" = "1" ]; then
    log "TEST_MODE: genererar self-signed TLS-certifikat..."
    openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
        -keyout /etc/cups/ssl/server.key \
        -out    /etc/cups/ssl/server.crt \
        -subj   "/CN=localhost" \
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
        2>/dev/null
    chmod 640 /etc/cups/ssl/server.key
    chown root:lp /etc/cups/ssl/server.key
else
    err "TLS-certifikat saknas: /etc/cups/secrets/server.crt"
fi

# -----------------------------------------------------------------------------
# Kerberos keytab (hoppas över i testläge)
# -----------------------------------------------------------------------------
if [ -f /etc/cups/secrets/cups.keytab ]; then
    log "Installerar Kerberos keytab..."
    cp /etc/cups/secrets/cups.keytab /etc/cups/cups.keytab
    chmod 640 /etc/cups/cups.keytab
    chown root:lp /etc/cups/cups.keytab
elif [ "${TEST_MODE:-0}" = "1" ]; then
    log "TEST_MODE: Kerberos keytab hoppas över"
else
    err "Kerberos keytab saknas: /etc/cups/secrets/cups.keytab"
fi

# -----------------------------------------------------------------------------
# Verifiera att miljövariabler finns
# I testläge krävs inte LDAP-variabler (ersätts av CERT_STORE_PATH)
# -----------------------------------------------------------------------------
if [ "${TEST_MODE:-0}" = "1" ]; then
    required_vars=(S3_ENDPOINT S3_ACCESS_KEY S3_SECRET_KEY S3_BUCKET DATABASE_URL)
else
    required_vars=(
        LDAP_HOST LDAP_BIND_DN LDAP_BIND_PASSWORD LDAP_BASE_DN
        S3_ENDPOINT S3_ACCESS_KEY S3_SECRET_KEY S3_BUCKET
        DATABASE_URL
    )
fi
for var in "${required_vars[@]}"; do
    if [ -z "${!var:-}" ]; then
        err "Miljövariabel saknas: $var"
    fi
done
log "Alla miljövariabler finns"

# -----------------------------------------------------------------------------
# Starta CUPS i bakgrunden för initial konfiguration
# -----------------------------------------------------------------------------
log "Startar CUPS..."
cupsd -f &
CUPS_PID=$!

# Vänta tills CUPS svarar
log "Väntar på CUPS-scheduler..."
for i in $(seq 1 20); do
    if lpstat -r 2>/dev/null | grep -q "scheduler is running"; then
        log "CUPS igång"
        break
    fi
    sleep 1
    if [ "$i" -eq 20 ]; then
        err "CUPS svarade inte inom 20 sekunder"
    fi
done

# -----------------------------------------------------------------------------
# Skapa kön om den inte finns (idempotent)
# -----------------------------------------------------------------------------
if ! lpstat -p s3-queue 2>/dev/null | grep -q "s3-queue"; then
    log "Skapar utskriftskö 's3-queue'..."
    # s3-policy är definierad i produktions-cupsd.conf men inte i testlägets config
    POLICY_OPT=(-o printer-op-policy=s3-policy)
    [ "${TEST_MODE:-0}" = "1" ] && POLICY_OPT=()
    lpadmin \
        -p s3-queue \
        -E \
        -v "s3print://" \
        -D "Säker krypterad utskriftskö" \
        "${POLICY_OPT[@]}" \
        -o printer-is-accepting-jobs=true
    log "Kön 's3-queue' skapad"
else
    log "Kön 's3-queue' finns redan"
fi

# -----------------------------------------------------------------------------
# Kör CUPS i förgrunden (PID 1)
# -----------------------------------------------------------------------------
log "CUPS redo – väntar på utskrifter"
wait $CUPS_PID
