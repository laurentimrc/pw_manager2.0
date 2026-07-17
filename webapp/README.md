# Password Manager Pro — Webapp (React + FastAPI)

Interfaccia alternativa, con look moderno, all'app Streamlit esistente (`ps_manager_app.py`, alla radice del repository). Le due interfacce sono equivalenti dal punto di vista funzionale e condividono lo stesso vault locale (`passwords.json`, `master_pwd.hash`, `kdf.salt` nella radice del repo) tramite lo stesso modulo `password_manager.py`, che non viene duplicato né riscritto.

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
        ├── components/auth/           Setup e Login
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

## Avvio in sviluppo

### Backend (porta 8000, solo 127.0.0.1)

```bash
cd webapp/backend
pip install -r requirements.txt   # + requirements.txt della radice del repo (bcrypt, cryptography, pyotp, zxcvbn-python)
python -m uvicorn app.main:app --app-dir . --host 127.0.0.1 --port 8000
```

Il backend usa di default `passwords.json`, `master_pwd.hash`, `kdf.salt` nella **radice del repository** (stesso vault dell'app Streamlit). Per puntare altrove (es. nei test), sovrascrivi con le variabili d'ambiente `PWM_HASH_FILE`, `PWM_SALT_FILE`, `PWM_DB_FILE`.

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
