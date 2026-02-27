#!/bin/bash
# =============================================================================
# Driftsättningsskript för secure-print i OpenShift
# Kör från projektets rotkatalog
# =============================================================================
set -euo pipefail

NAMESPACE="secure-print"
REGISTRY="registry.company.com/secure-print"
IMAGE_TAG="${1:-latest}"

log()  { echo "[deploy] $*"; }
err()  { echo "[deploy] ERROR: $*" >&2; exit 1; }
step() { echo; echo "── $* ──"; }

# Kontrollera att oc är inloggad
oc whoami &>/dev/null || err "Inte inloggad i OpenShift. Kör: oc login"

# -----------------------------------------------------------------------------
step "Namespace och RBAC"
# -----------------------------------------------------------------------------
oc apply -f openshift/namespace.yaml
oc apply -f openshift/serviceaccount.yaml

# -----------------------------------------------------------------------------
step "Bygg och pusha container"
# -----------------------------------------------------------------------------
log "Bygger image..."
podman build -t "${REGISTRY}/cups:${IMAGE_TAG}" docker/

log "Pushar image..."
podman push "${REGISTRY}/cups:${IMAGE_TAG}"

# -----------------------------------------------------------------------------
step "Secrets – kontrollera att de finns"
# -----------------------------------------------------------------------------
for secret in cups-env-secrets cups-tls cups-keytab; do
    if ! oc get secret "$secret" -n "$NAMESPACE" &>/dev/null; then
        err "Secret '$secret' saknas. Skapa med instruktionerna i secret.yaml.template"
    fi
    log "Secret '$secret' finns"
done

# -----------------------------------------------------------------------------
step "Databas"
# -----------------------------------------------------------------------------
log "Applicerar schema (kräver databasåtkomst)..."
log "Kör manuellt: psql \$DATABASE_URL -f sql/schema.sql"

# -----------------------------------------------------------------------------
step "ConfigMap"
# -----------------------------------------------------------------------------
oc apply -f openshift/configmap.yaml

# -----------------------------------------------------------------------------
step "Deployment, Service och Route"
# -----------------------------------------------------------------------------
# Sätt rätt image-tag i deployment
sed "s|cups:latest|cups:${IMAGE_TAG}|g" openshift/deployment.yaml | oc apply -f -
oc apply -f openshift/service.yaml
oc apply -f openshift/route.yaml
oc apply -f openshift/cronjob-cleanup.yaml

# -----------------------------------------------------------------------------
step "Väntar på rollout"
# -----------------------------------------------------------------------------
oc rollout status deployment/cups -n "$NAMESPACE" --timeout=120s

# -----------------------------------------------------------------------------
step "Status"
# -----------------------------------------------------------------------------
oc get pods    -n "$NAMESPACE" -l app=cups
oc get route   -n "$NAMESPACE" cups-ipps

log "Driftsättning klar!"
log "CUPS nås på: ipps://$(oc get route cups-ipps -n $NAMESPACE -o jsonpath='{.spec.host}'):631"
