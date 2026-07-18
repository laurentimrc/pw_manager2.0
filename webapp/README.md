# Password Manager Pro — Webapp (React + FastAPI)

Interfaccia alternativa, con look moderno, all'app Streamlit esistente (`ps_manager_app.py`, alla radice del repository). Le due interfacce condividono lo stesso vault locale (`passwords.json`, `master_pwd.hash`, `kdf.salt`, `vault_key.json` nella radice del repo) tramite lo stesso modulo `password_manager.py`, che non viene duplicato né riscritto. Sono equivalenti per setup/login/credenziali/cambio master password; il **recovery della master password dimenticata** ha una UI dedicata SOLO qui (vedi sotto) — Streamlit continua a funzionare invariato attraverso la stessa logica di dominio, ma senza un modo per avviare il recovery da quell'interfaccia.

⚠️ Stesso disclaimer del progetto principale: applicazione didattica, non pensata per credenziali reali/critiche senza una revisione di sicurezza approfondita.

## Architettura

```
webapp/
├── backend/            FastAPI (Python), riusa password_manager.py dalla radice del repo
│   ├── app/
│   │   ├── main.py     endpoint HTTP, CORS, wiring sessione/lockout
│   │   ├── config.py   percorsi file dati, parametri lockout/sessione, override via env
│   │   ├── sessions.py SessionStore (in-memory) + LoginGuard (lockout)
│   │   └── schemas.py  modelli Pydantic delle richieste
│   ├── tests/
│   │   └── test_api.py test FastAPI (TestClient), stesso stile dei test esistenti
│   └── requirements.txt
└── frontend/            React + TypeScript + Vite, Tailwind CSS, componenti in stile shadcn/ui
    └── src/
        ├── App.tsx                    orchestrazione setup/login/app autenticata
        ├── AuthenticatedApp.tsx       shell con sidebar + routing tra le viste
        ├── lib/api.ts                 client HTTP verso il backend (fetch, credentials: 'include')
        ├── components/auth/           Setup, Login, reveal codice di recovery, flusso "password dimenticata"
        ├── components/credentials/    lista, form aggiunta/modifica, generatore, TOTP, copia rapida
        ├── components/dashboard/      Dashboard di Sicurezza
        ├── components/utility/        Export / Import / Cambio Master Password
        └── components/ui/             primitive riutilizzabili (Button, Card, Badge, Tabs, ...)
```

### Perché FastAPI + React invece di estendere Streamlit

Streamlit non separa lato server/client in modo esplicito (tutto il rendering è server-driven), il che rende difficile ottenere componenti UI curati e un vero routing client-side. FastAPI espone la logica di dominio già pura di `password_manager.py` come API HTTP, e React se ne occupa lato client con controllo fine su UX/stile. Il tradeoff principale: due processi da avviare invece di uno, e un modello di sessione HTTP (cookie) da gestire esplicitamente al posto di `st.session_state`.

### Modello di sessione e sicurezza

- Il backend ascolta **solo** su `127.0.0.1` (vedi comando di avvio sotto).
- Dopo login/setup, la master password (necessaria per ri-derivare il cipher Fernet, es. in fase di cambio Master Password) e il cipher Fernet già derivato vivono **solo in memoria di processo del backend**, indicizzati da un session id opaco (`secrets.token_urlsafe(32)`), esattamente come `st.session_state` in Streamlit. Il browser riceve solo un cookie **httpOnly, SameSite=Strict** con quel session id: non vede mai la master password né la chiave derivata. Non c'è persistenza su disco delle sessioni: un riavvio del backend le invalida tutte.
- **Lockout login**: 5 tentativi falliti, poi cooldown di 60 secondi (stato globale al processo, dato che l'app è single-user).
- **Timeout di sessione**: 15 minuti di inattività (calcolati sulle richieste autenticate reali, non su polling in background — coerente con `last_activity` di Streamlit, aggiornato solo alle interazioni utente).
- La lista credenziali **non include mai la password** in chiaro; va richiesta esplicitamente via `GET /api/credentials/{service}/secret` (usato per "Mostra password", "Copia" e il precompilamento del form di modifica).
- CORS ristretto alla sola origine del dev server Vite (default `http://127.0.0.1:5173`), non wildcard.
- Import/validazione backup riusa `validate_imported_db`; lista/badge di sicurezza riusano `compute_security_flags`/`sort_credentials`; nessuna logica di dominio duplicata nel backend.

### Recovery della Master Password dimenticata (solo webapp)

Tutta la logica vive in `password_manager.py` (condivisa con Streamlit), il backend si limita a esporla via HTTP:

- Le credenziali sono criptate con una **DEK** (Data Encryption Key) casuale, non derivata dalla master password. La DEK è "avvolta" (wrapped, criptata con Fernet) da due KEK indipendenti: una dalla master password + `kdf.salt` (come prima), una da un **codice di recovery** ad alta entropia (~100 bit, formato leggibile `XXXX-XXXX-XXXX-XXXX-XXXX`) + un salt separato. Tutto questo materiale vive in `vault_key.json`; il codice di recovery in chiaro non è mai salvato su disco.
- Al setup (`POST /api/auth/setup`) e, per i vault creati prima di questa funzionalità, al primo login riuscito successivo (`POST /api/auth/login`, migrazione automatica e trasparente), la risposta include un campo `recovery_code` **una tantum**: il frontend lo mostra in una schermata dedicata con conferma esplicita ("ho salvato il codice") prima di proseguire, come i backup code 2FA.
- Flusso "Hai dimenticato la Master Password?" (dalla schermata di login):
  1. `POST /api/auth/recover/verify` — verifica il codice contro l'hash bcrypt salvato, senza toccare la DEK: dà un errore chiaro e immediato ("codice non valido") prima ancora di far scegliere una nuova master password.
  2. `POST /api/auth/recover` — codice + nuova master password: sblocca la DEK con la KEK di recovery, ri-avvolge la DEK con la nuova KEK master, e genera/salva un **nuovo** codice di recovery (quello usato è a uso singolo e da questo momento non è più valido). Nessuna sessione viene creata da questa chiamata: l'utente torna alla schermata di login e accede con la nuova master password.
- `change_master_password` non ri-cripta più ogni singola credenziale: si limita a ri-avvolgere la DEK esistente con la nuova KEK master (la DEK stessa non cambia). Il codice di recovery non viene ruotato da un cambio "volontario" della master password, solo da un uso effettivo del recovery.

### Controllo violazioni note (solo webapp)

La Dashboard di Sicurezza include un controllo su richiesta esplicita (bottone "Controlla violazioni note") che verifica se le password salvate compaiono in violazioni di dati pubblicamente note, usando l'API "Pwned Passwords" di Have I Been Pwned (HIBP):

- `check_password_breach` (in `password_manager.py`, condivisa e testata senza dipendenze da `streamlit`) calcola l'hash SHA-1 della password **solo in locale** e invia in rete esclusivamente il prefisso a 5 caratteri esadecimali di quell'hash (modello **k-anonymity**, `GET https://api.pwnedpasswords.com/range/{prefix}`); il confronto col suffisso della password reale avviene interamente nel processo backend. Né la password in chiaro né l'hash SHA-1 completo lasciano mai il processo, in nessun log o risposta HTTP.
- Usa `urllib.request` della standard library (nessuna nuova dipendenza runtime: il modulo `password_manager.py` non aveva finora alcuna dipendenza di rete). Non solleva mai eccezioni verso il chiamante: un fallimento (rete assente, timeout, API non raggiungibile) restituisce `None`, distinto dal conteggio `0` ("nessuna violazione nota").
- `POST /api/credentials/{service}/breach-check` controlla una singola credenziale; `POST /api/security/breach-check` controlla tutte le credenziali in un'unica azione esplicita, deduplicando le password uguali (una sola chiamata HIBP per le password riutilizzate) e senza bloccare le altre se una chiamata fallisce. **Nessuno dei due endpoint fa mai un controllo automatico al caricamento della dashboard**, sia per rispetto verso un'API gratuita di terzi sia per non introdurre round-trip di rete non richiesti.
- Il frontend distingue visivamente tre stati per credenziale: *trovata in N violazioni*, *nessuna violazione nota*, *controllo non riuscito* (quest'ultimo non va mai confuso col secondo: significa solo che non è stato possibile verificare, non che la password sia sicura).

## Avvio in sviluppo

### Backend (porta 8000, solo 127.0.0.1)

```bash
cd webapp/backend
pip install -r requirements.txt   # + requirements.txt della radice del repo (bcrypt, cryptography, pyotp, zxcvbn-python)
python -m uvicorn app.main:app --app-dir . --host 127.0.0.1 --port 8000
```

Il backend usa di default `passwords.json`, `master_pwd.hash`, `kdf.salt`, `vault_key.json` nella **radice del repository** (stesso vault dell'app Streamlit). Per puntare altrove (es. nei test), sovrascrivi con le variabili d'ambiente `PWM_HASH_FILE`, `PWM_SALT_FILE`, `PWM_DB_FILE`, `PWM_KEY_FILE`.

### Frontend (porta 5173)

```bash
cd webapp/frontend
npm install
npm run dev
```

Apri **`http://127.0.0.1:5173`** (non `localhost`: i cookie di sessione sono legati all'host `127.0.0.1` usato dal backend, e `localhost`/`127.0.0.1` sono host diversi ai fini dei cookie).

## Test

```bash
# Backend (FastAPI TestClient, dati su directory temporanee — non tocca il vault reale)
python -m pytest webapp/backend/tests/

# Frontend: build + type-check
cd webapp/frontend
npm run build
```

## Cosa manca rispetto a un rollout di produzione

- Nessun rate limiting/CSRF token oltre a SameSite=Strict (adeguato per uso locale mono-utente, non per esposizione di rete).
- Il cookie di sessione è impostato con `secure=False` in sviluppo (HTTP locale); va impostato `PWM_COOKIE_SECURE=true` se servito dietro HTTPS.
- Nessun build/packaging di produzione del frontend servito dal backend (in sviluppo sono due processi separati); per un pacchetto distribuibile andrebbe aggiunto uno step che serva `webapp/frontend/dist/` da FastAPI o da un reverse proxy.
