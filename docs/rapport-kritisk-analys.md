# Kritisk analys – Secure Print

**Datum:** 2026-03-03
**Version:** 1.0
**Granskade filer:** `terminal-app/app_qt.py`, `docker/s3print`, `docker-compose.yml`, `sql/schema.sql`, `terminal-app/install.sh`, `terminal-app/secure-print-terminal.service`, `terminal-app/requirements-qt.txt`

---

## Sammanfattning

Secure Print är ett välstrukturerat proof-of-concept med en tydlig säkerhetsfilosofi: krypterad spoolning i S3, smartkortsautentisering i terminalen och ingen klartext på nätverket. Grundarkitekturen är sund, men det finns ett antal brister på säkerhets-, drifts- och funktionsnivå som måste åtgärdas innan systemet kan betraktas som produktionsmoget. Rapporten identifierar 4 kritiska/höga säkerhetsproblem, 6 saknade funktioner samt en rad drifts- och underhållsproblem.

---

## 1. Säkerhet

### 1.1 Unauthenticated kryptering (KRITISK)

**Fil:** `docker/s3print` rad 157–168
**Problem:** Kryptering sker med `openssl cms -encrypt -aes-256-cbc`. CBC-läge ger **konfidentialitet men inte integritet**. Det finns ingen MAC eller autentiseringstagг. En angripare med skrivbehörighet till S3-bucketen kan manipulera det krypterade jobbinnehållet (padding oracle, bitflip-attack) utan att det syns vid dekryptering.
**Rekommendation:** Byt till AES-256-GCM (AEAD) eller lägg till ett HMAC-SHA256 av den krypterade filen, signerat med en tjänstnyckel. Alternativt: använd `openssl cms -encrypt` med `-aes-256-gcm` om det stöds av OpenSSL-versionen, eller byt till ett explicit GCM-flöde via `cryptography`-biblioteket utan subprocess.

---

### 1.2 PIN sparas i Python-sträng utan minnessanering (HÖG)

**Fil:** `terminal-app/app_qt.py` rad 482 (`LoginWorker.__init__`), 1162–1163 (`MainWindow._login_ok`)
**Problem:** PIN-koden lagras i `self._pin` som en Python-sträng. Python-strängar är immutabla och kan inte nollsättas; objektet lever i minnet tills garbage collectorn väljer att frigöra det. Ännu allvarligare: `self._pin` i `MainWindow` rensas inte explicit vid utloggning – `_logout()` sätter `self._upn = self._cert_pem = ""` men **inte** `self._pin = ""`.
**Konsekvens:** PIN-koden kan förbli i processminnets heap efter utloggning, synlig i en core dump eller minnesdump.
**Rekommendation:**
1. Nollsätt `self._pin = ""` i `_logout()` och `_on_card_removed()`.
2. På längre sikt: använd `bytearray` i stället för `str` för PIN, och skriv explicita nollor (`pin_buf[:] = b'\x00' * len(pin_buf)`) efter användning. Python garanterar fortfarande inget om intern minnesåtervinning, men det är bättre praxis.

---

### 1.3 Revokationskontroll i mjukt läge – "fail open" (HÖG)

**Fil:** `terminal-app/app_qt.py` rad 376–378
**Problem:** Om varken OCSP-servern eller CRL-distributionspunkten är nåbar (nätverksavbrott, DDoS, felkonfiguration) loggas en varning och inloggning **tillåts ändå** (mjukt läge). Ett återkallat certifikat kan alltså användas under en nätverkspartition.

```python
# rad 376-378
if REVOCATION_CHECK == "strict":
    raise ValueError("Revokationsstatus kunde inte fastställas (REVOCATION_CHECK=strict)")
log.warning("REVOCATION: Varken OCSP eller CRL nåddes – inloggning tillåts (mjukt läge)")
```

**Rekommendation:** Produktionsmiljöer bör köra med `REVOCATION_CHECK=strict`. Dokumentera tydligt att standardvärdet `ocsp` (mjukt läge) är en medveten kompromiss för driftsstabilitet, inte ett säkerhetsval. Överväg OCSP-stapling eller en lokal OCSP-cache (t.ex. `openssl ocsp -nmin 60` med caching) för att minska beroendet av extern tillgänglighet.

---

### 1.4 OCSP-responsens signatur verifieras ej om utfärdarens certifikat saknas (HÖG)

**Fil:** `terminal-app/app_qt.py` rad 301–305

```python
if issuer_file.exists():
    cmd += ["-issuer", str(issuer_file)]
else:
    cmd += ["-noverify"]
    log.warning("REVOCATION: OCSP utan utfärdarens certifikat – responssignatur verifieras ej")
```

**Problem:** Om utfärdarens certifikat inte kan hämtas från AIA-extensionen faller koden tillbaka på `-noverify`. Det innebär att en MitM-angripare (eller komprometterad DNS) kan svara med ett falskt OCSP-svar som säger `good` för ett återkallat certifikat.
**Rekommendation:** Bunta med utfärdar-CA-certifikaten i `/etc/secure-print/ca-bundle.pem` och konfigurera `REVOCATION_CA_FILE` att peka dit. Ta bort `-noverify`-grenen; misslyckas utfärdarupp­slagningen ska OCSP betraktas som ej avgörande och CRL provas.

---

### 1.5 CRL-integriteten verifieras inte (MEDEL)

**Fil:** `terminal-app/app_qt.py` rad 335–340
**Problem:** `load_der_x509_crl(crl_data)` laddar CRL:en utan att verifiera CA-signaturen. Koden kontrollerar om ett serienummer finns i listan men validerar inte att CRL:en faktiskt är signerad av rätt CA.
**Rekommendation:** Anropa `crl.is_signature_valid(public_key)` med CA:ns publika nyckel, eller använd openssl-subprocess (`openssl crl -verify -CAfile ...`). Avvisa CRL om signaturen är ogiltig.

---

### 1.6 Hårdkodade testlösenord i versionshantering (MEDEL – testmiljö)

**Fil:** `docker-compose.yml` rad 16–17, 34–35, 77–80

```yaml
POSTGRES_PASSWORD: printpass
MINIO_ROOT_PASSWORD: minioadmin123
```

**Problem:** Lösenorden är hårdkodade i `docker-compose.yml` som är incheckad i git. Även om detta är en testmiljö skapar det dålig vana och risk om filen råkar kopieras till produktion.
**Rekommendation:** Flytta lösenord till `.env`-fil (gitignorerad) och referera dem med `${VAR}`-syntax i compose-filen. Lägg `.env.example` i repot i stället.

---

### 1.7 Obegränsad S3-nedladdning (MEDEL)

**Fil:** `terminal-app/app_qt.py` rad 396–397

```python
def download_from_s3(s3_key: str) -> bytes:
    resp = _s3().get_object(Bucket=S3_BUCKET, Key=s3_key)
    return resp["Body"].read()
```

**Problem:** Hela S3-objektet läses in i RAM utan storleksbegränsning. En felaktig eller manipulerad post i databasen med en stor S3-nyckel kan orsaka OOM på terminalen.
**Rekommendation:** Sätt en maxgräns (t.ex. 500 MB) och avbryt nedladdningen om objektstorleken (från `ContentLength`) överskrider den. Logga och visa ett felmeddelande i UI:t.

---

### 1.8 Saknade systemd-härdningar (LÅG)

**Fil:** `terminal-app/secure-print-terminal.service`
**Problem:** Tjänsten saknar `ProtectHome=yes`, `PrivateUsers=yes`, `RestrictNamespaces=yes` och `SystemCallFilter=`.
**Rekommendation:** Lägg till:

```ini
ProtectHome=yes
PrivateUsers=yes
RestrictNamespaces=yes
SystemCallFilter=@system-service
```

---

## 2. Funktioner

### 2.1 Inga S3-objekt rensas efter hämtning

**Fil:** `terminal-app/app_qt.py` rad 563; `sql/schema.sql` rad 47–56
**Problem:** `mark_retrieved()` markerar jobbet som `retrieved` i databasen men tar **inte** bort S3-objektet. Den krypterade jobbfilen ligger kvar i S3 tills `expire_old_jobs()` anropas – men den funktionen returnerar bara nycklar att rensa och anropas inte automatiskt av någon CronJob, systemd-timer eller liknande. I praktiken ackumuleras krypterade jobb i S3 utan rensning.
**Rekommendation:**
1. Ta bort S3-objektet direkt i `PrintWorker.run()` efter lyckad utskrift.
2. Implementera ett K8s CronJob (eller systemd-timer) som kör `expire_old_jobs()` och sedan raderar de returnerade S3-nycklarna.

---

### 2.2 Ingen automatiserad utgånghantering

**Konsekvens av 2.1:** Jobb med status `pending` som aldrig hämtas (t.ex. användaren kom aldrig) förblir kvar i S3 och tas inte bort. `expires_at`-kolumnen och `expire_old_jobs()`-funktionen finns men anropas aldrig i nuvarande implementation.

---

### 2.3 Ingen utskriftsåterförsök (retry)

**Fil:** `terminal-app/app_qt.py` rad 567–569
**Problem:** Om `lpr` misslyckas (skrivaren är offline, pappersstopp) betraktas jobbet som `retrieved` och tas bort från listan. Användaren måste skicka om jobbet från sin dator.
**Rekommendation:** Separera `mark_retrieved()` från utskriftssteget. Markera bara jobbet som hämtat om `lpr` lyckades. Låt misslyckade utskrifter förbli `pending` (upp till N försök) och visa ett specifikt felmeddelande i UI:t.

---

### 2.4 Inga hälsokontroller för Kubernetes

**Problem:** Ingen `/healthz`- eller `/readyz`-endpoint finns i CUPS-containern. Kubernetes kan inte avgöra om CUPS-podden är redo att ta emot jobb.
**Rekommendation:** Lägg till en HTTP-hälsoendpoint i CUPS-containern (t.ex. ett enkelt Python-script som anropar `lpstat -r`) och konfigurera `livenessProbe`/`readinessProbe` i K8s-deploymentet.

---

### 2.5 Ingen mätvärdesexponering (metrics/observability)

**Problem:** Systemet saknar Prometheus-metrics. Det är omöjligt att utan att gå igenom loggar se:
- Antal jobb per dag/timme
- Misslyckade utskrifter
- PIN-felfrekvens per terminal
- S3-bucket-storlek

**Rekommendation:** Exponera grundläggande räknare via ett enkelt `prometheus_client`-bibliotek i s3print (eller som en sidecar) och i terminalen (om driftsättd centralt).

---

### 2.6 Ingen certifikatutgångvarning

**Problem:** Varken systemet eller terminalen varnar när ett användarcertifikat (på smartkortet) snart löper ut. Användaren stoppas helt vid inloggning när certifikatet gått ut, utan förvarning.
**Rekommendation:** Kontrollera `not_valid_after` efter lyckad autentisering. Visa en varning i JobsScreen om certifikatet löper ut inom 30 dagar.

---

## 3. Användarvänlighet

### 3.1 Ingen progressindikator vid nedladdning och dekryptering

**Fil:** `terminal-app/app_qt.py` rad 535–565 (`PrintWorker.run`)
**Problem:** Användaren ser ingen feedback under det som kan vara flera sekunder av S3-nedladdning och PKCS#11-dekryptering. UI:t "fryser" (ur användarens perspektiv) tills `success`- eller `failure`-signalen emitteras.
**Rekommendation:** Visa ett statusmeddelande i `_status_label` ("Hämtar utskrift…", "Dekrypterar…", "Skriver ut…") med framstegsuppdateringar via extra signaler från `PrintWorker`.

---

### 3.2 Antal kvarvarande PIN-försök visas inte

**Problem:** YubiKey/smartkortet låser sig efter N felaktiga PIN-försök (typiskt 3 för PIV). Terminalen ger inget återkoppling om hur många försök som återstår före låsning.
**Rekommendation:** Fånga `pkcs11.exceptions.PinIncorrect` och försök hämta `CKA_ALWAYS_SENSITIVE`-attributet för att uppskatta kvarvarande försök, alternativt räkna lokalt och visa "X försök kvar" i `PINScreen`.

---

### 3.3 Bulk-utskrift kan konflikt med smartkortsläsaren

**Fil:** `terminal-app/app_qt.py` rad 1202–1211 (`_do_bulk_print`)
**Problem:** Bulk-utskrift startar ett `PrintWorker`-tråd per jobb parallellt. Varje tråd öppnar en PKCS#11-session mot smartkortet. De flesta PKCS#11-implementationer (OpenSC inkluderat) stöder inte parallella sessioner utan `CKF_OS_LOCKING_OK`. Risk för deadlock eller undantag.
**Rekommendation:** Kör bulk-utskrift sekventiellt (kö), eller öppna en enda PKCS#11-session och skicka den som parameter till `PrintWorker`.

---

### 3.4 Fem minuter inaktivitetstimeout kan vara för kort

**Problem:** En användare som skriver ut ett stort dokument (t.ex. 200-sidors rapport) och väntar vid skrivaren kan bli utloggad om skrivaren är långsam.
**Rekommendation:** Gör timeout konfigurerbar via `IDLE_TIMEOUT_MINUTES` i `terminal.env`. Standardvärde 10 minuter är rimligare för de flesta arbetsflöden.

---

### 3.5 Minnes-läcka: self._workers växer obegränsat

**Fil:** `terminal-app/app_qt.py` rad 1154, 1178, 1195 m.fl.
**Problem:** `self._workers.append(worker)` lägger till QThread-objekt men tar aldrig bort dem. Under ett skift med många utskrifter växer listan utan bound.
**Rekommendation:** Anslut `worker.finished` till en slot som tar bort den avslutade tråden ur listan:

```python
worker.finished.connect(lambda w=worker: self._workers.discard(w))
```

(eller använd en `set` i stället för `list`.)

---

## 4. Driftbarhet och förvaltning

### 4.1 Ingen databasanslutningspool

**Fil:** `terminal-app/app_qt.py` rad 400–401; `docker/s3print` rad 230

```python
def _db():
    return psycopg2.connect(DATABASE_URL)
```

**Problem:** Varje databasoperation öppnar en ny psycopg2-anslutning och stänger den i `finally`. Under hög belastning (t.ex. vid massbulk-utskrift) skapas många kortlivade anslutningar. Det är ineffektivt och kan orsaka `too many connections`-fel i PostgreSQL.
**Rekommendation:** Använd `psycopg2.pool.ThreadedConnectionPool` eller `psycopg2-pool` för att återanvända anslutningar.

---

### 4.2 PostgreSQL saknar hög tillgänglighet

**Problem:** Arkitekturen förutsätter en enda PostgreSQL-instans. Vid databaskrasch är hela systemet nere – varken utskrift eller inloggning fungerar.
**Rekommendation:** Dokumentera krav på HA-PostgreSQL (t.ex. Patroni, CloudSQL, RDS multi-AZ). Lägg till connection retry-logik med exponentiell backoff i `_db()`.

---

### 4.3 Ingen strukturerad loggning – SIEM-integration svår

**Problem:** Auditloggar skrivs som fri text:

```python
log.info(f"AUDIT login_ok upn={upn} terminal={TERMINAL_ID}")
```

Det är omöjligt att tillförlitligt parsa dessa med en SIEM (Splunk, Elastic, etc.) utan brittle regex.
**Rekommendation:** Byt till JSON-logging:

```python
log.info("audit", extra={"event": "login_ok", "upn": upn, "terminal": TERMINAL_ID})
```

med `python-json-logger` som handler.

---

### 4.4 cups_job_id spåras inte i auditloggen konsekvent

**Problem:** `cups_job_id` sparas i databasen men loggas inte konsekvent i auditloggarna. Det är svårt att korrelera en CUPS-loggpost med en terminalloggpost.
**Rekommendation:** Inkludera `cups_job_id` och `job_uuid` (UUID) i alla auditloggrader, både vid inlämning i `s3print` och vid hämtning i terminalen.

---

### 4.5 Ingen Helm-chart eller K8s-manifest

**Problem:** Presentationen och README nämner Kubernetes som driftsättningsmål men det finns inga K8s-manifest eller Helm-chart i repot.
**Rekommendation:** Skapa ett minimalt `k8s/`-katalog med `Deployment`, `Service`, `CronJob` (för `expire_old_jobs`) och `Secret`-referenser. En Helm-chart är ett plus men inte ett krav i fas 1.

---

### 4.6 S3 kommunicerar okrypterat i testmiljön

**Fil:** `docker-compose.yml` rad 77; `test/terminal-real.env` rad 5
**Problem:** `S3_ENDPOINT=http://minio:9000` och `S3_ENDPOINT=http://localhost:9000` använder HTTP. Jobbinnehållet är krypterat men metadata (objektnyckel, storlek, tidsstämplar) exponeras i klartext.
**Rekommendation:** Konfigurera MinIO med TLS i integrationstester. Dokumentera att produktion **måste** använda `https://`.

---

### 4.7 DISPLAY=:0 hårdkodat i systemd-tjänsten

**Fil:** `terminal-app/secure-print-terminal.service` rad 20
**Problem:** `DISPLAY=:0` fungerar för en enda fysisk skärm med X11. Det fungerar inte med Wayland (`WAYLAND_DISPLAY=wayland-0`) eller om displayen är på ett annat nummer.
**Rekommendation:** Gör `DISPLAY` och `QT_QPA_PLATFORM` konfigurerbara via `terminal.env` med rimliga standardvärden. Dokumentera Wayland-stöd (`QT_QPA_PLATFORM=wayland`).

---

### 4.8 CardMonitorThread saknar stoppmekanism

**Fil:** `terminal-app/app_qt.py` rad 462–473
**Problem:** `CardMonitorThread.run()` är en oändlig loop utan `stop()`-metod eller stop-event. Tråden kan inte avbrytas rent vid applikationsavslutning, vilket kan ge "orphaned thread"-varningar eller delayed shutdown.
**Rekommendation:** Lägg till ett `threading.Event` som loop-villkor:

```python
self._stop = threading.Event()
def run(self):
    while not self._stop.is_set():
        ...
        self._stop.wait(1)
def stop(self):
    self._stop.set()
```

---

## 5. Åtgärdsplan (prioriterad)

### Fas 0 – Omedelbart (före eventuell pilotdrift)

| # | Åtgärd | Fil | Allvarlighetsgrad |
|---|--------|-----|-------------------|
| 0.1 | Byt `aes-256-cbc` till AES-256-GCM eller lägg till HMAC | `docker/s3print` | KRITISK |
| 0.2 | Nollsätt `self._pin` i `_logout()` och `_on_card_removed()` | `terminal-app/app_qt.py` | HÖG |
| 0.3 | Byt standardvärde för `REVOCATION_CHECK` till `strict` i prod, dokumentera tydligt | `terminal-app/app_qt.py`, `terminal-app/install.sh` | HÖG |
| 0.4 | Bunta CA-certifikat, ta bort `-noverify`-grenen | `terminal-app/app_qt.py` | HÖG |
| 0.5 | Rensa S3-objektet i `PrintWorker` efter lyckad utskrift | `terminal-app/app_qt.py` | HÖG |
| 0.6 | Flytta testlösenord till gitignorerad `.env`-fil | `docker-compose.yml` | MEDEL |

### Fas 1 – Innan bredddrift (0–3 månader)

| # | Åtgärd | Fil |
|---|--------|-----|
| 1.1 | Verifiera CRL-signatur mot CA-cert | `terminal-app/app_qt.py` |
| 1.2 | Begränsa S3-nedladdning med storlekscheck | `terminal-app/app_qt.py` |
| 1.3 | Progressindikator i PrintWorker | `terminal-app/app_qt.py` |
| 1.4 | K8s CronJob för `expire_old_jobs()` + S3-rensning | Ny fil `k8s/cronjob-expire.yaml` |
| 1.5 | JSON-strukturerad auditloggning | `terminal-app/app_qt.py`, `docker/s3print` |
| 1.6 | Fixa minneslläcka i `self._workers` | `terminal-app/app_qt.py` |
| 1.7 | Sekventiell (inte parallell) bulk-utskrift | `terminal-app/app_qt.py` |

### Fas 2 – Kvalitetshöjning (3–6 månader)

| # | Åtgärd |
|---|--------|
| 2.1 | Psycopg2-anslutningspool |
| 2.2 | Retry-logik vid utskriftsfel (max 3 försök) |
| 2.3 | Certifikatutgångvarning (< 30 dagar) |
| 2.4 | Konfigurerbar inaktivitetstimeout |
| 2.5 | Systemd-härdning (ProtectHome, PrivateUsers) |
| 2.6 | Korrekt `CardMonitorThread.stop()` |

### Fas 3 – Enterprise-beredskap (6–12 månader)

| # | Åtgärd |
|---|--------|
| 3.1 | Helm-chart för K8s-driftsättning |
| 3.2 | Prometheus-metrics för CUPS-backend och terminal |
| 3.3 | Hälsokontrollendpoint för K8s |
| 3.4 | PostgreSQL HA-dokumentation och connection retry |
| 3.5 | OCSP-caching / OCSP stapling för reducerat nätverksberoende |
| 3.6 | i18n-stöd (om flerspråkig miljö krävs) |

---

## 6. Vad fungerar bra

Det är viktigt att lyfta fram vad som är genomtänkt och välgjort:

- **Ingen webserver, inga öppna portar på terminalen** – PyQt6-arkitekturen eliminerar Flask-attackytan.
- **FIFO-PIN-mekanism** – PIN berör aldrig disk; skickas via UNIX FIFO till OpenSSL-subprocessen. God säkerhetsdesign.
- **PrivateTmp=yes i systemd** – Dekrypterade temporärfiler är isolerade och rensas automatiskt vid processavslut.
- **S3-nyckelformat (`jobs/{upn}/{uuid}.cms`)** – Enkel åtkomstkontroll via bucket-policies per UPN-prefix.
- **`_SAFE_KEY`/`_SAFE_VALUE`-validering** – Command injection i `lpr`-argumenten förhindras med whitelist-regex.
- **Revokationskontroll med OCSP+CRL-fallback** – Implementerat och aktivt (om inte `none` konfigureras).
- **`NoNewPrivileges=yes`, `ProtectSystem=strict`** – Grundläggande systemd-härdning finns på plats.
- **UPN-baserad åtkomst** – Användaren kan bara se och hämta sina egna jobb (databasen filtrerar på `user_upn`).

---

*Rapport genererad genom manuell kodgranskning av Claude Code (claude-sonnet-4-6).*
