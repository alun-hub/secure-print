# =============================================================================
# Secure Print Terminal – demobild
#
# Simulerar ett smartkort med SoftHSM2. Kör Flask-terminalen mot den vanliga
# PostgreSQL/MinIO-stacken i docker-compose.yml.
#
# Bygg från projektets rotkatalog:
#   docker compose up --build terminal
# =============================================================================
FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    openssl \
    libengine-pkcs11-openssl \
    softhsm2 \
    opensc \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY terminal-app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY terminal-app/app.py .
COPY terminal-app/templates/ templates/
COPY test/gen-cert.py gen-cert.py
COPY terminal-app/docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

EXPOSE 5000
ENTRYPOINT ["/docker-entrypoint.sh"]
