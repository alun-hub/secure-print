FROM debian:bookworm-slim

# Installera beroenden
RUN apt-get update && apt-get install -y --no-install-recommends \
    # CUPS och Kerberos
    cups \
    cups-client \
    libpam-krb5 \
    krb5-user \
    # Kryptering
    openssl \
    # Python och LDAP/S3/PostgreSQL-bibliotek
    python3 \
    python3-ldap \
    python3-boto3 \
    python3-psycopg2 \
    # Verktyg
    uuid-runtime \
    && rm -rf /var/lib/apt/lists/*

# Skapa SSL-katalog
RUN mkdir -p /etc/cups/ssl && chmod 750 /etc/cups/ssl

# CUPS-konfiguration
COPY cupsd.conf /etc/cups/cupsd.conf

# Custom S3-backend
# chmod 700: körs som root av CUPS-scheduler
COPY s3print /usr/lib/cups/backend/s3print
RUN chmod 700 /usr/lib/cups/backend/s3print \
    && chown root:root /usr/lib/cups/backend/s3print

# Entrypoint
COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh

EXPOSE 631

HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD lpstat -r 2>/dev/null | grep -q "scheduler is running" || exit 1

ENTRYPOINT ["/entrypoint.sh"]
