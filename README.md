# Secure Print

End-to-end encrypted pull printing system built on standard components.
Print jobs are encrypted with the recipient's public key before storage —
even the print server cannot read the content. Jobs are only decrypted
at the physical printer using the user's smartcard.

```
Client (Linux/Windows)
       │
       │  IPPS + Kerberos (TLS 1.2+)
       ▼
┌─────────────────────────────┐
│  CUPS  (OpenShift / K8s)    │  ← receives job, authenticates via AD
│  s3print backend            │  ← encrypts + stores, never spools locally
└────────┬────────────────────┘
         │  AES-256-CBC (CMS envelope, RSA/EC public key)
         ▼
┌────────────────┐    ┌──────────────────────┐
│  S3 / MinIO    │    │  PostgreSQL           │
│  job.cms files │    │  job metadata + index │
└────────┬───────┘    └──────────┬────────────┘
         │                       │
         └──────────┬────────────┘
                    │  Flask API (localhost only)
                    ▼
        ┌───────────────────────┐
        │  Thin terminal        │  ← Chromium kiosk, touch screen
        │  Flask + PKCS#11      │  ← decrypts with smartcard private key
        └──────────┬────────────┘
                   │  lpr (IPP)
                   ▼
            [ Local printer ]
```

## Security model

| Threat | Mitigation |
|--------|-----------|
| Eavesdropping on print submission | IPPS (IPP over TLS 1.2+), Kerberos ticket proves identity |
| Unauthorised job retrieval | Job encrypted with recipient's public key; ciphertext useless without smartcard |
| Impersonating another user at terminal | PIN-protected smartcard; private key never leaves the card (PKCS#11) |
| Server compromise | Server only holds ciphertext; private key is on the user's card |
| Forgotten job left in queue | Configurable expiry (default 48 h); CronJob purges S3 + DB |
| Stolen smartcard | PIN required for every decryption operation |

## Components

| Component | Technology | Purpose |
|-----------|-----------|---------|
| Print spooler | CUPS + IPPS | Receives jobs over encrypted IPP; authenticates via Kerberos |
| Kerberos auth | Active Directory / MIT KDC | Binds submitted job to the user's UPN without passwords on the wire |
| Encryption backend | `docker/s3print` (Python) | CUPS custom backend; encrypts each job with the user's X.509 public key |
| Certificate source | LDAP / AD (`userCertificate`) | Backend fetches the recipient's DER certificate at submission time |
| Job store | S3 / MinIO | Holds encrypted CMS blobs; keys are `jobs/<upn>/<uuid>.cms` |
| Job index | PostgreSQL | Stores metadata (UPN, title, S3 key, status, expiry) |
| Terminal UI | Flask + Chromium kiosk | Touch-friendly web UI running locally on the thin terminal |
| Smartcard runtime | OpenSC + PKCS#11 | PIN verification and private-key decryption without key extraction |
| Job cleanup | Kubernetes CronJob | Hourly: marks expired rows, deletes corresponding S3 objects |

---

## Repository layout

```
secure-print/
├── docker/                  # CUPS container (runs in OpenShift)
│   ├── Dockerfile
│   ├── cupsd.conf           # CUPS config: TLS, Kerberos, job policy
│   ├── entrypoint.sh        # Bootstraps TLS/keytab, creates print queue
│   └── s3print              # Python CUPS backend (encrypt → S3 → PostgreSQL)
│
├── sql/
│   └── schema.sql           # Table, indexes, expiry view, expire_old_jobs()
│
├── openshift/               # Kubernetes / OpenShift manifests
│   ├── namespace.yaml
│   ├── serviceaccount.yaml  # + anyuid SCC binding (CUPS needs root)
│   ├── configmap.yaml       # krb5.conf, non-secret settings
│   ├── secret.yaml.template # Instructions + template for all secrets
│   ├── deployment.yaml      # 2 replicas, topology spread, health probes
│   ├── service.yaml         # ClusterIP on port 631
│   ├── route.yaml           # OpenShift Route, TLS passthrough (required for Kerberos)
│   ├── cronjob-cleanup.yaml # Hourly expired-job cleanup
│   └── deploy.sh            # One-shot deployment script
│
└── terminal-app/            # Thin terminal software (runs on the device)
    ├── app.py               # Flask: card monitor, PIN auth, S3 download, decrypt, print
    ├── templates/
    │   └── index.html       # Single-page kiosk UI (vanilla JS, no framework)
    ├── requirements.txt
    ├── secure-print-terminal.service   # systemd unit
    └── install.sh           # Interactive installer for Debian/Raspberry Pi
```

---

## Print submission flow

```
1. User prints from any application (Word, LibreOffice, lpr, …)

2. OS sends job via IPPS to spooler.company.com:631
   Windows 10/11: built-in IPP Everywhere – no driver needed
   Linux:         lpadmin -p myprinter -v ipps://spooler.company.com:631/printers/s3-queue

3. CUPS authenticates the connection via Kerberos (HTTP Negotiate)
   The job attribute job-originating-user-name is set to the verified UPN
   e.g.  anna.svensson@company.com

4. CUPS invokes the s3print backend (docker/s3print):
   a. Reads job data from stdin (PDF / PostScript)
   b. Looks up anna's certificate in AD/LDAP  (userCertificate attribute)
   c. Encrypts with:  openssl cms -encrypt -aes-256-cbc -recip anna_cert.pem
   d. Uploads ciphertext to S3:  jobs/anna.svensson@company.com/<uuid>.cms
   e. Inserts row in PostgreSQL:  (id, user_upn, title, s3_key, expires_at, status='pending')
   f. Returns exit 0 → CUPS marks job complete

5. CUPS spool is empty. No job data persists on the server.
```

## Print release flow

```
1. User walks to the printer, inserts smartcard

2. Chromium kiosk (http://localhost:5000) detects card via PKCS#11 polling

3. Numeric PIN pad appears on screen – user enters PIN

4. Flask backend (app.py):
   a. Opens PKCS#11 session with the PIN – fails fast on wrong PIN / locked card
   b. Reads certificate from card → extracts UPN from SAN otherName (OID 1.3.6.1.4.1.311.20.2.3)

5. Job list is fetched from PostgreSQL WHERE user_upn = '<upn>' AND status = 'pending'

6. User taps "Skriv ut" on a job

7. Flask backend:
   a. Verifies job ownership in PostgreSQL
   b. Downloads ciphertext from S3
   c. Decrypts:  openssl cms -decrypt -engine pkcs11 -inkey pkcs11:type=private
      Private key never leaves the smartcard; PKCS#11 engine performs RSA/EC inside the card
   d. Sends plaintext to local printer:  lpr -P <LOCAL_PRINTER>
   e. Marks row as  status='retrieved'  in PostgreSQL

8. Confirmation shown for 3 s, then job list refreshes

9. User removes card → Flask session cleared, PIN pad reappears
```

---

## Prerequisites

### CUPS server (OpenShift)
- OpenShift 4.x or Kubernetes 1.26+
- Active Directory with:
  - A service account for CUPS with an HTTP SPN: `HTTP/spooler.company.com`
  - A keytab exported for that account
  - Users with `userCertificate` attribute populated (AD CS or external CA)
- S3-compatible object store (MinIO, Ceph RGW, AWS S3, …)
- PostgreSQL 14+
- Internal CA certificate trusted by all clients (for IPPS)
- Container registry reachable from OpenShift

### Thin terminal
- Debian 12 (Bookworm) or Raspberry Pi OS (64-bit)
- PC/SC-compatible smartcard reader (USB or built-in)
- Network access to PostgreSQL and S3
- Local CUPS queue pointing to the physical printer
- Display + Chromium (for the kiosk UI)

---

## Deployment

### 1. PostgreSQL schema

```bash
psql "$DATABASE_URL" -f sql/schema.sql
```

### 2. Secrets (OpenShift)

```bash
# TLS certificate for CUPS (issued by your internal CA)
oc create secret generic cups-tls \
  --from-file=tls.crt=server.crt \
  --from-file=tls.key=server.key \
  -n secure-print

# Kerberos keytab (generated by AD admin via ktpass)
oc create secret generic cups-keytab \
  --from-file=cups.keytab=cups.keytab \
  -n secure-print

# Environment variables (see secret.yaml.template for all keys)
oc create secret generic cups-env-secrets \
  --from-literal=LDAP_HOST=dc1.company.com \
  --from-literal=LDAP_BIND_DN='CN=cups-svc,OU=ServiceAccounts,DC=company,DC=com' \
  --from-literal=LDAP_BIND_PASSWORD='...' \
  --from-literal=LDAP_BASE_DN='DC=company,DC=com' \
  --from-literal=S3_ENDPOINT=https://minio.company.com \
  --from-literal=S3_ACCESS_KEY='...' \
  --from-literal=S3_SECRET_KEY='...' \
  --from-literal=S3_BUCKET=secure-print-jobs \
  --from-literal=DATABASE_URL='postgresql://user:pass@host/db' \
  -n secure-print
```

### 3. Build and deploy to OpenShift

```bash
cd openshift
bash deploy.sh 1.0.0
```

The deployment script:
1. Builds the container image with `podman build`
2. Pushes to your registry
3. Applies all manifests in order
4. Waits for rollout to complete

### 4. Configure Windows clients

Add printer → "Add by address":
```
https://spooler.company.com:631/printers/s3-queue
```
Windows 10/11 discovers the IPP Everywhere driver automatically.
Domain-joined machines authenticate via Kerberos silently — no prompt.

### 5. Configure Linux clients

```bash
lpadmin -p secure-print \
        -v ipps://spooler.company.com:631/printers/s3-queue \
        -E
```

### 6. Install on thin terminal

```bash
sudo bash terminal-app/install.sh
```

The script installs system packages, creates a Python venv, registers a
systemd service, and configures Chromium to start in kiosk mode.

---

## Configuration reference

### CUPS backend (`s3print`) environment variables

| Variable | Description |
|----------|-------------|
| `LDAP_HOST` | LDAP/AD server hostname |
| `LDAP_BIND_DN` | Service account DN for LDAP queries |
| `LDAP_BIND_PASSWORD` | Service account password |
| `LDAP_BASE_DN` | Search base for user lookups |
| `S3_ENDPOINT` | S3-compatible endpoint URL |
| `S3_ACCESS_KEY` | S3 access key |
| `S3_SECRET_KEY` | S3 secret key |
| `S3_BUCKET` | Bucket name for encrypted jobs |
| `DATABASE_URL` | PostgreSQL connection string |
| `JOB_RETENTION_HOURS` | Hours before a job expires (default: `48`) |

### Terminal app (`/etc/secure-print/terminal.env`)

| Variable | Description |
|----------|-------------|
| `DATABASE_URL` | PostgreSQL connection string (read-only user recommended) |
| `S3_ENDPOINT` | S3-compatible endpoint URL |
| `S3_ACCESS_KEY` | S3 access key |
| `S3_SECRET_KEY` | S3 secret key |
| `S3_BUCKET` | Same bucket as above |
| `LOCAL_PRINTER` | CUPS printer name on this terminal (from `lpstat -p`) |
| `TERMINAL_ID` | Identifier logged in the `retrieved_by` column |
| `PKCS11_LIB` | Path to PKCS#11 library (default: OpenSC on x86-64) |

---

## Database schema

```sql
print_jobs
  id              UUID        PRIMARY KEY
  cups_job_id     INTEGER
  user_upn        VARCHAR     NOT NULL        -- anna.svensson@company.com
  title           VARCHAR     NOT NULL
  copies          INTEGER     NOT NULL
  s3_key          VARCHAR     NOT NULL        -- jobs/<upn>/<uuid>.cms
  encrypted_size  BIGINT      NOT NULL
  submitted_at    TIMESTAMPTZ NOT NULL
  expires_at      TIMESTAMPTZ NOT NULL        -- submitted_at + retention
  status          VARCHAR     NOT NULL        -- pending | retrieved | cancelled | expired
  retrieved_at    TIMESTAMPTZ
  retrieved_by    VARCHAR                     -- terminal ID
```

The `pending_jobs` view filters to `status = 'pending' AND expires_at > NOW()`.

---

## Horizontal scaling

Multiple CUPS pods can run concurrently because **no job data is stored in
the pod**. The `s3print` backend processes each job immediately:
encrypt → S3 → PostgreSQL → exit 0. The CUPS spool (`emptyDir`) is
empty between submissions.

The OpenShift `Deployment` is configured with:
- `replicas: 2` (adjust as needed)
- `topologySpreadConstraints` to distribute pods across nodes
- `maxUnavailable: 0` for zero-downtime rolling updates

---

## Observability

| What | Where |
|------|-------|
| Job submissions | `journalctl -u cups` (backend logs to stderr → CUPS log) |
| Job releases | `journalctl -u secure-print-terminal` on each terminal |
| Audit trail | `print_jobs` table: every submission, retrieval, and cancellation |
| Expired jobs | `print_jobs WHERE status = 'expired'` |

---

## Extending the system

**Add email notification on job receipt**
Add a `notify_user()` call in `s3print` after `register_in_db()`.
The UPN is a valid email address in most AD environments.

**Support multiple printers per terminal**
Set `LOCAL_PRINTER=ask` in `terminal.env` and add a printer-selection
step to the UI before the job list.

**RFID/NFC badge instead of PIN**
Replace the PIN pad in `index.html` with a badge-read event.
In `app.py`, replace `authenticate_card(pin)` with a badge-to-UPN lookup
and skip PIN verification (lower security, higher convenience).

---

## License

MIT
