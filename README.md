# Secure Print

End-to-end encrypted pull printing system built on standard components.
Print jobs are encrypted with the recipient's public key before leaving the
submission host — the print server stores only ciphertext and never has access
to the plaintext document. Jobs are released exclusively at the physical printer
by the intended recipient using their PIN-protected smartcard.

![Pin](pics/pin.png)
![Main GUI](pics/main-gui.png)

---

## Architecture overview

```
  PC / Workstation
  (Windows, Linux, macOS)
         │
         │  IPPS (IPP over TLS 1.2+)
         │  HTTP Negotiate / Kerberos – identity proven by AD ticket
         ▼
┌──────────────────────────────────────────────────┐
│  CUPS  (OpenShift / Kubernetes pod)              │
│                                                  │
│  ┌─────────────────────────────────────────────┐ │
│  │  s3print backend  (docker/s3print)          │ │
│  │                                             │ │
│  │  1. Read job from stdin (PS/PDF)            │ │
│  │  2. Fetch user cert from AD/LDAP            │ │
│  │  3. Encrypt: openssl cms -aes-256-gcm       │ │
│  │  4. Upload ciphertext → S3                  │ │
│  │  5. Insert metadata → PostgreSQL            │ │
│  │  6. Exit 0  (CUPS spool stays empty)        │ │
│  └──────────────────────��──────────────────────┘ │
└────────────┬─────────────────────────────────────┘
             │
             ├──────── AES-256-GCM (CMS envelope) ────────────┐
             │                                                 │
             ▼                                                 ▼
  ┌─────────────────────┐                       ┌─────────────────────────┐
  │  S3 / MinIO         │                       │  PostgreSQL             │
  │                     │                       │                         │
  │  jobs/<upn>/<uuid>  │                       │  print_jobs             │
  │  .cms               │                       │  (metadata + status)    │
  └──────────┬──────────┘                       └────────────┬────────────┘
             │                                               │
             └─────────────────────┬─────────────────────────┘
                                   │
                                   │  psycopg2 / boto3 (direct, no open ports)
                                   ▼
                       ┌───────────────────────────┐
                       │  Thin terminal            │
                       │                           │
                       │  PyQt6 native app         │
                       │  PKCS#11 (python-pkcs11)  │
                       │                           │
                       │  1. Card detected         │
                       │  2. PIN entered           │
                       │  3. UPN extracted         │
                       │  4. Jobs listed           │
                       │  5. Decrypt (on-card)     │
                       │  6. lpr → local printer   │
                       └───────────────────────────┘
                                   │
                                   │  lpr (IPP), with preserved
                                   │  duplex/paper/colour options
                                   ▼
                            [ Local printer ]
```

---

## Security model
## High-level system diagram

```mermaid
flowchart TB

subgraph CLIENT["User Workstation"]
    PC["Windows / Linux / macOS"]
end

subgraph OPENSHIFT["OpenShift / Kubernetes"]
    CUPS["CUPS\nIPPS 631"]
    BACKEND["s3print backend"]
    CRON["Cleanup CronJob"]
end

subgraph SERVICES["Internal Services"]
    AD["Active Directory / LDAP"]
    DB["PostgreSQL"]
    S3["S3 / MinIO"]
end

subgraph TERMINAL["Thin Terminal"]
    APP["PyQt6 App + PKCS#11"]
    CARD["Smartcard"]
    PRINTER["Local Printer"]
end

PC -->|IPPS + Kerberos| CUPS
CUPS --> BACKEND
BACKEND -->|LDAP query| AD
BACKEND -->|Ciphertext| S3
BACKEND -->|Metadata| DB
CRON --> DB
CRON --> S3

APP -->|Read jobs| DB
APP -->|Download| S3
APP -->|Decrypt| CARD
APP -->|lpr| PRINTER
```
---

## IPP Everywhere

**IPP Everywhere** (also marketed as Apple AirPrint and used by the Windows
built-in IPP Class Driver) is a driverless printing standard from the Printer
Working Group (PWG). Clients speak plain IPP or IPPS (IPP over TLS) — no
vendor driver is installed on the workstation.

### How it works in this system

```
Client workstation                 CUPS (OpenShift)          Thin terminal
──────────────────                 ────────────────          ─────────────
Windows 10/11, macOS,
Linux — no driver needed

  User prints PDF/Word
         │
         │ IPPS (port 631, TLS 1.2+)
         │ HTTP Negotiate / Kerberos
         │
         ▼
  s3-queue printer ──────────────► s3print backend
  (raw passthrough,                Reads job as-is (PDF/PS)
   no filter chain)                Encrypts → S3 + PostgreSQL
                                   Exit 0 – spool cleared

                                                    User walks to printer
                                                    Inserts smartcard
                                                            │
                                                            ▼
                                                    PyQt6 terminal app
                                                    Downloads from S3
                                                    Decrypts on-card
                                                            │
                                                            │ lpr
                                                            ▼
                                                    Local CUPS queue
                                                    (driver lives here)
                                                            │
                                                            ▼
                                                       Printer
```

### No driver required — on either side

The submission queue (`s3-queue`) has **no PPD and no filter chain**. It
accepts raw PostScript or PDF and passes it straight to the `s3print` backend,
which stores the bytes unmodified in S3. This means:

- **Clients need zero driver installation** — Windows, macOS, and Linux all
  print natively via their built-in IPP stack.
- Print settings (duplex, paper size, colour mode, n-up) are captured from
  CUPS `argv[5]` as a JSON dict and stored alongside the ciphertext in
  PostgreSQL.
- At release time the terminal sends the decrypted PS/PDF via `lpr` to the
  local CUPS printer. For any printer that supports **IPP Everywhere**, CUPS
  uses the `ipp` backend directly — no driver, no filter chain, no PPD. The
  printer handles rendering natively.

For older printers that do not support IPP Everywhere, `install.sh` offers
traditional options (Generic PostScript, hplip, Gutenprint, custom PPD).
In those cases CUPS on the terminal does apply a filter chain, but that is the
exception rather than the rule.

This split is intentional: the encryption boundary is the submission server.
What the terminal feeds to the printer is plaintext, but it never leaves the
local network segment and is released only after PIN-authenticated smartcard
decryption.

### Client setup (one-time, per workstation)

**Windows 10/11** — Add a printer by address:
```
https://spooler.company.com:631/printers/s3-queue
```
Windows discovers capabilities via IPP `Get-Printer-Attributes` and installs
the built-in Microsoft IPP Class Driver automatically. Domain-joined machines
authenticate via Kerberos silently.

**macOS** — System Settings → Printers → Add → enter the same URL. AirPrint
handles the rest.

**Linux (CUPS)**:
```bash
lpadmin -p secure-print \
        -v ipps://spooler.company.com:631/printers/s3-queue \
        -E
```

---

# Security model

## End-to-end flow

```mermaid
sequenceDiagram

participant User
participant PC
participant CUPS
participant s3print
participant AD as Active Directory
participant S3
participant DB
participant Terminal
participant Card as Smartcard
participant Printer

User->>PC: Print document
PC->>CUPS: IPPS (TLS) + Kerberos
CUPS->>s3print: Job + options

s3print->>AD: Fetch certificate
s3print->>s3print: Encrypt (CMS AES-256-GCM)
s3print->>S3: Upload ciphertext
s3print->>DB: Insert metadata

User->>Terminal: Insert card
Terminal->>Card: PIN auth
Card-->>Terminal: OK

Terminal->>DB: Fetch jobs
Terminal->>S3: Download ciphertext
Terminal->>Card: Decrypt
Card-->>Terminal: Plaintext
Terminal->>Printer: Print
Terminal->>DB: status=retrieved
Terminal->>S3: Delete ciphertext
```

---

### Threat mitigations

| Threat | Mitigation |
|--------|-----------|
| Eavesdropping on job submission | IPPS (IPP over TLS 1.2+) for all client–server traffic |
| Identity spoofing at submission | Kerberos (HTTP Negotiate); the AD ticket cryptographically binds the job to the user's UPN — no password sent |
| Unauthorised job retrieval | Job encrypted with recipient's X.509 public key; ciphertext is useless without the private key on the smartcard |
| Server compromise | Server stores only ciphertext and metadata; private key never leaves the smartcard |
| Impersonating another user at terminal | PIN-protected PKCS#11 session; wrong PIN or locked card → authentication fails immediately |
| Private key extraction | PKCS#11 decryption runs inside the smartcard; the key never enters host memory |
| Forgotten job left in queue | Configurable retention (default 48 h); hourly CronJob marks expired rows and deletes S3 objects |
| Cancelled job data lingering in S3 | Cancelled jobs are also purged by the hourly CronJob (same expiry logic) |
| Retrieved job ciphertext lingering in S3 | Terminal deletes the S3 object immediately after a successful print; no residual ciphertext remains at rest |
| Stolen smartcard | PIN required; repeated wrong PINs lock the card |
| Session left open at terminal | Client-side inactivity timer (5 min) auto-logs out; card removal immediately clears session |
| Command injection via print options | Option keys and values validated with strict regex before passing to `lpr`; subprocess list (not shell) prevents injection regardless |
| XSS / web attack surface at terminal | Eliminated: the terminal is a native PyQt6 app with no web server and no browser — there is no HTML surface to inject into |
| Job metadata exposure | Terminal API returns only `options_summary` (human-readable string), never the raw options JSON |

### Encryption details

```
Algorithm:   CMS (PKCS#7 / RFC 5652) enveloped-data
Symmetric:   AES-256-GCM  (data encryption key, AEAD — RFC 5084)
             GCM provides both confidentiality and integrity (authentication
             tag). Any tampering of the ciphertext in S3 is detected at
             decrypt time.
Asymmetric:  RSA or EC    (encrypts the AES key for the recipient)

Encryption:  openssl cms -encrypt -binary -aes-256-gcm -recip <cert.pem>
             -binary is required to treat input as raw binary data (PDF/PS).
             Without it, openssl applies MIME canonicalisation and silently
             stops reading at MIME-special sequences inside the document.

Decryption:  openssl cms -decrypt -binary \
               -provider pkcs11 -provider default \
               -inkey 'pkcs11:type=private;pin-source=file:<fifo>'
             Uses the OpenSSL 3.x PKCS#11 provider (not the deprecated engine).
             PIN is passed via a kernel FIFO — never written to disk.
             Decrypted output is captured via stdout (never written to a file).
             The PKCS#11 provider performs RSA/EC unwrap inside the smartcard;
             the private key never enters host memory.
```

### Network exposure

| Component | Listens on | Protocol |
|-----------|-----------|---------|
| CUPS (OpenShift) | `0.0.0.0:631` (via Route) | IPPS (TLS 1.2+) |
| PostgreSQL | internal cluster / VPN | TCP (TLS recommended) |
| S3 / MinIO | internal cluster / VPN | HTTPS |

The terminal application opens **no listening ports**. It connects outbound to
PostgreSQL and S3 only; all communication is client-initiated.

---

## Print options preservation

Print settings selected by the user (duplex, paper size, colour mode, n-up, etc.)
travel through the entire pipeline and are applied at the physical printer.

```
PC                        CUPS backend (s3print)          Terminal (app_qt.py)
────────────────────────────────────────────────────────────────────────��─
lpr -o sides=two-sided    argv[5] parsed by               build_lpr_cmd() reads
    -o media=A4            parse_cups_options()            options from DB and
    -o print-color-mode=                                   constructs:
       monochrome          {"sides": "two-sided-…",        lpr -P printer -# 2
                            "media": "A4",                     -o sides=two-sided-…
                            "print-color-mode":                -o media=A4
                              "monochrome"}                    -o print-color-mode=
                                                                  monochrome
                           Stored as JSON in
                           print_jobs.options
```

**Option validation** in `build_lpr_cmd()`:
- Keys: `^[a-zA-Z0-9_\-]+$`
- Values: `^[a-zA-Z0-9_\-\./: ]+$`
- `copies` key is stripped (handled separately by `-#`)
- Passed as a subprocess list — shell injection is architecturally impossible

**UI display**: `summarize_options()` converts raw option values to readable text
(e.g. `"Dubbelsidig · A4 · Svartvitt"`) shown on each job card in the terminal.

---

## Audit logging

All security-relevant events are written to the system journal
(`journalctl -u secure-print-terminal`) with a structured `AUDIT` prefix
for easy filtering.

### Terminal events

| Event | Log message |
|-------|------------|
| Login success | `AUDIT login_ok upn=… terminal=…` |
| Login failure | `AUDIT login_fail terminal=… reason=…` |
| Job printed | `AUDIT print_ok upn=… job_id=… title=… terminal=…` |
| Print failure | `AUDIT print_fail upn=… job_id=… terminal=… error=…` |
| Job cancelled | `AUDIT cancel upn=… job_id=… terminal=…` |
| Logout | `AUDIT logout upn=… terminal=…` |
| Unauthorised API call | `AUDIT unauthorized endpoint=… terminal=…` |

### CUPS backend events

| Event | Log message |
|-------|------------|
| Job received | `Tar emot jobb … från 'upn': title (copies, options=…)` |
| Job stored | `AUDIT job_submitted upn=… job_id=… title=… copies=… size=…` |
| DB rollback | `Databasfel: …` + S3 object deleted |

### Database audit trail

Every job carries a full lifecycle in `print_jobs`:

```
submitted_at  → when the job was spooled
status        → pending | retrieved | cancelled | expired
retrieved_at  → when the terminal released it
retrieved_by  → which terminal (TERMINAL_ID)
```

Filter example:
```sql
-- All jobs printed in the last 7 days, by whom and on which terminal
SELECT user_upn, title, copies, retrieved_at, retrieved_by
FROM   print_jobs
WHERE  status = 'retrieved'
  AND  retrieved_at > NOW() - INTERVAL '7 days'
ORDER  BY retrieved_at DESC;
```

---

## Detailed flows

### Job submission

```
1. User prints from any application (Word, LibreOffice, lpr, …)

2. OS sends the job via IPPS to spooler.company.com:631
     Windows 10/11: built-in IPP Everywhere – no client driver needed
     Linux: lpadmin -p secure-print \
                    -v ipps://spooler.company.com:631/printers/s3-queue -E

3. CUPS authenticates via Kerberos (HTTP Negotiate)
   The job attribute job-originating-user-name is set to the verified UPN,
   e.g. anna.svensson@company.com

4. CUPS passes all job options (duplex, paper, colour, etc.) to the backend
   via argv[5] as a space-separated key=value string.

5. s3print backend (docker/s3print) runs:
   a. Parses argv[5] → options dict (copies stripped, handled separately)
   b. Reads job data from stdin (PDF / PostScript – no pre-processing)
   c. Looks up anna's X.509 certificate from AD/LDAP (userCertificate)
   d. Encrypts: openssl cms -encrypt -binary -aes-256-gcm -recip anna_cert.pem
   e. Uploads ciphertext to S3: jobs/anna.svensson@company.com/<uuid>.cms
   f. Inserts row in PostgreSQL:
      (id, user_upn, title, copies, options_json, s3_key, expires_at, 'pending')
   g. Returns exit 0 → CUPS marks the job complete and empties the spool

6. No job data persists on the CUPS server.
```

### Job release

```
1. User walks to the printer, inserts smartcard into reader

2. CardMonitorThread (polls _check_card_present() every 1 s) emits
   card_inserted → MainWindow switches to PINScreen

3. PIN pad appears; user enters PIN via touchscreen or physical keyboard
   OK is disabled until ≥ 4 digits are entered

4. LoginWorker (QThread) calls authenticate_card(pin):
   a. Opens PKCS#11 session with the PIN
      → raises ValueError immediately on wrong PIN or locked card
   b. Reads certificate from card (DER → PEM via openssl x509)
   c. Extracts UPN from SAN otherName OID 1.3.6.1.4.1.311.20.2.3
   d. Runs check_revocation(): OCSP → CRL fallback (configurable)

5. JobLoaderWorker (QThread) fetches jobs from PostgreSQL:
   SELECT … FROM pending_jobs WHERE user_upn = '<upn>'
   Results displayed as JobCard widgets in a scrollable list.
   User can tap "Uppdatera" at any time to reload without logging out.

6. User taps "Skriv ut" on a job, or checks multiple cards and taps
   "Skriv ut valda (N)" for bulk print

7. PrintWorker (QThread) for each job:
   a. Downloads ciphertext from S3 (boto3)
   b. Decrypts via PKCS#11 (OpenSSL 3.x provider):
        openssl cms -decrypt -binary -provider pkcs11 -provider default \
          -inkey 'pkcs11:type=private;pin-source=file:<fifo>'
      PIN is passed via a kernel FIFO — never written to disk.
      Private key never leaves the card; RSA/EC unwrap runs in hardware.
      Decrypted data captured via stdout → format-detected temp file
      (.pdf / .ps) so local CUPS applies the correct filter chain.
   c. Sends plaintext to local printer, preserving original print settings:
        lpr -P <LOCAL_PRINTER> -# <copies>
            -o sides=<…> -o media=<…> -o print-color-mode=<…> …
   d. Marks row as status='retrieved', sets retrieved_at and retrieved_by
   e. Deletes the ciphertext from S3 immediately (no residual data at rest)
   f. Job list reloads automatically when all pending workers complete

8. User removes card → CardMonitorThread emits card_removed →
   session variables wiped from memory, WaitScreen shown immediately
```

### Job expiry and cleanup

```
Hourly (Kubernetes CronJob: openshift/cronjob-cleanup.yaml):

1. Calls PostgreSQL function expire_old_jobs():
   UPDATE print_jobs
   SET    status = 'expired'
   WHERE  status IN ('pending', 'cancelled')   ← both statuses
     AND  expires_at < NOW()
   RETURNING s3_key

2. For each returned s3_key:
   s3.delete_object(Bucket=…, Key=s3_key)

Cancelled jobs are cleaned up by the same CronJob (they carry the original
expires_at from submission, so they are purged within 48 h at most).
```

---

## Repository layout

```
secure-print/
├── docker/                       CUPS container (runs in OpenShift)
│   ├── Dockerfile
│   ├── cupsd.conf                CUPS config: TLS, Kerberos, job policy
│   ├── entrypoint.sh             Bootstraps TLS cert + keytab, creates print queue
│   └── s3print                   Python CUPS backend
│                                   parse_cups_options() → encrypt → S3 → PostgreSQL
│
├── sql/
│   └── schema.sql                Table definition, indexes, pending_jobs view,
│                                 expire_old_jobs() function
│                                 Migration comment for existing deployments included
│
├── openshift/                    Kubernetes / OpenShift manifests
│   ├── namespace.yaml
│   ├── serviceaccount.yaml       + anyuid SCC binding (CUPS needs root)
│   ├── configmap.yaml            krb5.conf, non-secret settings
│   ├── secret.yaml.template      Instructions + template for all secrets
│   ├── deployment.yaml           2 replicas, topology spread, health probes
│   ├── service.yaml              ClusterIP on port 631
│   ├── route.yaml                OpenShift Route, TLS passthrough (Kerberos requirement)
│   ├── cronjob-cleanup.yaml      Hourly: expire pending+cancelled jobs, delete S3 objects
│   └── deploy.sh                 One-shot deployment script
│
└── terminal-app/                 Thin terminal software (runs on the device)
    ├── app_qt.py                 Native PyQt6 app: card monitor, PIN pad, job list,
    │                             bulk print/cancel, PKCS#11 decrypt, lpr, audit logging
    ├── requirements-qt.txt       PyQt6, psycopg2-binary, boto3, python-pkcs11, cryptography
    ├── app.py                    Flask version (kept for Docker demo container only)
    ├── templates/
    │   └── index.html            Web UI used by the Docker demo
    ├── requirements.txt          Flask dependencies (Docker demo only)
    ├── secure-print-terminal.service   systemd unit (ExecStart → app_qt.py)
    └── install.sh                Interactive installer: packages, CUPS + printer driver,
                                  PKCS11_LIB auto-detection, Python venv, systemd
```

---

## Database schema

```sql
print_jobs
  id               UUID        PRIMARY KEY
  cups_job_id      INTEGER                         -- CUPS internal job number
  user_upn         VARCHAR     NOT NULL            -- anna.svensson@company.com
  title            VARCHAR     NOT NULL            -- document name
  copies           INTEGER     NOT NULL DEFAULT 1
  options          TEXT        NOT NULL DEFAULT '{}' -- JSON: {"sides":"two-sided-…", …}
  s3_key           VARCHAR     NOT NULL            -- jobs/<upn>/<uuid>.cms
  encrypted_size   BIGINT      NOT NULL            -- bytes, for UI display
  submitted_at     TIMESTAMPTZ NOT NULL
  expires_at       TIMESTAMPTZ NOT NULL            -- submitted_at + JOB_RETENTION_HOURS
  status           VARCHAR     NOT NULL            -- pending|retrieved|cancelled|expired
  retrieved_at     TIMESTAMPTZ
  retrieved_by     VARCHAR                         -- terminal TERMINAL_ID
```

**Migration for existing deployments:**
```sql
ALTER TABLE print_jobs ADD COLUMN options TEXT NOT NULL DEFAULT '{}';
```

**Views:**
- `pending_jobs` — filters `status = 'pending' AND expires_at > NOW()`;
  includes `options` column; used by the terminal app

---

## Prerequisites

### CUPS server (OpenShift)

- OpenShift 4.x or Kubernetes 1.26+
- Active Directory:
  - Service account with HTTP SPN: `HTTP/spooler.company.com`
  - Keytab exported for that account (`ktpass`)
  - Users with `userCertificate` attribute populated (AD CS or external CA)
- S3-compatible object store (MinIO, Ceph RGW, AWS S3, …)
- PostgreSQL 14+
- Internal CA certificate trusted by all clients (for IPPS)
- Container registry reachable from OpenShift

### Thin terminal

- Debian 12 (Bookworm) or Raspberry Pi OS 64-bit
- PC/SC-compatible smartcard reader (USB or built-in)
- Network access to PostgreSQL and S3 (no inbound ports required)
- Display with X11 or Wayland support (for the PyQt6 native UI)
- A network-attached or USB printer supported by CUPS

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

# Environment variables (see openshift/secret.yaml.template for all keys)
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

The script builds the container image with `podman build`, pushes to your
registry, applies all manifests in order, and waits for the rollout to complete.

### 4. Configure clients (Windows / macOS / Linux)

See [IPP Everywhere](#ipp-everywhere) above for per-OS instructions.
Domain-joined Windows machines authenticate via Kerberos silently.

### 5. Install on thin terminal

```bash
cd terminal-app
sudo bash install.sh
```

The interactive script:
1. Installs system packages (`cups`, `opensc`, `pcscd`, `python3-pyqt6`, …)
2. Enables `pcscd` and `cups` system services
3. Creates a restricted `secprint` system user
4. Builds a Python virtual environment and installs `requirements-qt.txt`
5. **Auto-detects PKCS11_LIB path** from architecture (x86-64, ARM64, ARMhf)
6. Prompts for PostgreSQL / S3 credentials and terminal ID
7. **Configures the local printer in CUPS** (see Printer drivers below)
8. Writes `/etc/secure-print/terminal.env` (mode 600, owned by `secprint`)
9. Installs and enables the `secure-print-terminal` systemd service
   (`app_qt.py` started directly by systemd with `DISPLAY=:0`)

#### Printer drivers

When `install.sh` runs the printer setup step it offers five options:

| Option | When to use |
|--------|------------|
| **IPP Everywhere** (recommended) | Any network printer manufactured after ~2013 with IPP support. No driver package needed. |
| **Generic PostScript** | Older PostScript printers without IPP Everywhere support. |
| **HP (hplip)** | HP printers requiring duplex, stapling, or tray selection. `hplip` is installed; PPD auto-detected from `lpinfo -m`. |
| **Gutenprint** | Canon, Epson, and other inkjet/laser models. `printer-driver-gutenprint` installed; PPD path prompted. |
| **Custom PPD** | Manufacturer-supplied `.ppd` file (Konica-Minolta, Ricoh, Xerox, etc.). |

For printers that support IPP Everywhere no driver is needed anywhere in the
pipeline. Traditional driver packages (hplip, Gutenprint, vendor PPD) are
available for older hardware that requires them.

---

## Configuration reference

### CUPS backend — `s3print` environment variables

| Variable | Description |
|----------|-------------|
| `LDAP_HOST` | LDAP/AD server hostname |
| `LDAP_BIND_DN` | Service account DN for LDAP queries |
| `LDAP_BIND_PASSWORD` | Service account password |
| `LDAP_BASE_DN` | Search base for user lookups |
| `S3_ENDPOINT` | S3-compatible endpoint URL |
| `S3_ACCESS_KEY` | S3 access key |
| `S3_SECRET_KEY` | S3 secret key |
| `S3_BUCKET` | Bucket name for encrypted job files |
| `DATABASE_URL` | PostgreSQL connection string |
| `JOB_RETENTION_HOURS` | Hours until a job expires (default: `48`) |
| `CERT_STORE_PATH` | *(test mode only)* Path to JSON file mapping UPN → PEM cert |
| `TEST_MODE` | Set to `1` to skip Kerberos and use `CERT_STORE_PATH` |

### Terminal app — `/etc/secure-print/terminal.env`

| Variable | Description |
|----------|-------------|
| `DATABASE_URL` | PostgreSQL connection string (read-only user recommended) |
| `S3_ENDPOINT` | S3-compatible endpoint URL |
| `S3_ACCESS_KEY` | S3 access key |
| `S3_SECRET_KEY` | S3 secret key |
| `S3_BUCKET` | Same bucket as the backend |
| `LOCAL_PRINTER` | CUPS printer name on this terminal (verify with `lpstat -p`) |
| `TERMINAL_ID` | Unique identifier for this terminal; logged in `retrieved_by` |
| `PKCS11_LIB` | Path to PKCS#11 shared library (auto-detected by `install.sh`) |
| `REVOCATION_CHECK` | Certificate revocation mode: `ocsp` (default, with CRL fallback), `strict` (hard fail if status unknown), `none` (disabled — **not for production**) |

**PKCS11_LIB paths by architecture:**

| Architecture | Path |
|---|---|
| x86-64 (PC) | `/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so` |
| ARM64 (Raspberry Pi 4/5) | `/usr/lib/aarch64-linux-gnu/opensc-pkcs11.so` |
| ARMhf (Raspberry Pi 3) | `/usr/lib/arm-linux-gnueabihf/opensc-pkcs11.so` |

---

## Terminal UI features

The terminal is a fullscreen native PyQt6 application (`app_qt.py`) with three
screens managed by a `QStackedWidget`:

**WaitScreen** — shown when no card is present
- Smartcard icon, "Sätt i smartkort" prompt, terminal ID and printer name

**PINScreen** — shown when a card is inserted
- 3×4 numeric keypad (touchscreen) + physical keyboard support
- Dot-row showing digit count without revealing the PIN
- Inline error message (wrong PIN, locked card) in red
- OK disabled until ≥ 4 digits entered

**JobsScreen** — shown after successful authentication
- Job cards: title, copies, options summary, file size, submission time
- **Checkbox per card** for multi-select
- **"Markera alla / Avmarkera alla"** toggle
- **"Skriv ut valda (N)"** and **"Ta bort valda (N)"** bulk-action buttons,
  visible only when at least one card is selected
- **"Uppdatera"** reloads the job list without logging out
- **"Logga ut"** clears session and returns to WaitScreen
- Empty state: "Inga utskrifter i kö"

**Session management**
- **Print options summary** — e.g. `Dubbelsidig · A4 · Svartvitt` from stored JSON
- **Inactivity timeout** — 5-minute idle timer resets on any mouse/key/touch event; auto-logout on expiry
- **Card removal** — `CardMonitorThread` detects removal within 1 s; session variables wiped, WaitScreen shown immediately
- **No data on disk** — UPN, cert PEM, and PIN are held only in instance variables for the duration of the session

---

## Horizontal scaling

Multiple CUPS pods can run concurrently because **no job data is stored in
the pod**. The `s3print` backend processes each job atomically:
encrypt → S3 upload → PostgreSQL insert → exit 0. The CUPS spool (`emptyDir`)
is empty between submissions.

If the PostgreSQL insert fails, the S3 object is deleted (rollback) and CUPS
retries the job. No orphaned objects accumulate on partial failure.

The OpenShift `Deployment` is configured with:
- `replicas: 2` (adjust as needed)
- `topologySpreadConstraints` distributes pods across nodes
- `maxUnavailable: 0` for zero-downtime rolling updates

---

## Local test environment

```bash
# Start PostgreSQL, MinIO and CUPS with the s3print backend
docker compose up -d

# Generate test certificate + SoftHSM2 token
bash test/setup.sh

# Send a test job with print options
bash test/send-job.sh

# Or manually with options:
lpr -H localhost:631 -P s3-queue \
    -o sides=two-sided-long-edge \
    -o media=A4 \
    -o print-color-mode=monochrome \
    testjob.ps

# Inspect the database
psql "postgresql://printuser:printpass@localhost/secure_print" \
     -c "SELECT user_upn, title, copies, options, status FROM print_jobs;"

# MinIO web console: http://localhost:9001  (minioadmin / minioadmin123)
```

---

## Observability

| What | Where |
|------|-------|
| Job submissions | `[s3print]` prefix in CUPS log / pod stderr |
| AUDIT events (terminal) | `journalctl -u secure-print-terminal` — grep for `AUDIT` |
| AUDIT events (backend) | Pod logs — grep for `AUDIT` |
| Job lifecycle | `SELECT * FROM print_jobs ORDER BY submitted_at DESC` |
| Expired/cancelled jobs | `SELECT * FROM print_jobs WHERE status IN ('expired','cancelled')` |
| S3 storage | MinIO console or `aws s3 ls s3://secure-print-jobs/ --recursive` |

---

## Extending the system

**Email notification on job receipt**
Add a `notify_user()` call in `s3print` after `register_in_db()`.
The UPN is a valid email address in most AD environments.

**Multiple printers per terminal**
Set `LOCAL_PRINTER=ask` in `terminal.env` and add a printer-selection
step to the UI before the job list is shown.

**RFID / NFC badge instead of PIN**
Replace `PINScreen` in `app_qt.py` with a badge-read event (e.g. via a
serial/HID reader connected to a `QThread`).
Replace `authenticate_card(pin)` with a badge-to-UPN lookup
and skip PKCS#11 PIN verification (lower security, higher convenience).

**Admin CLI**
The `expire_old_jobs()` PostgreSQL function can be called externally.
An admin script can force-expire individual jobs, list all jobs across users,
and report S3 storage usage without touching the application code.

---

## License

MIT
```

