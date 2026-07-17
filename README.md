# Password Manager Pro 🔑

Un'applicazione web semplice ma funzionale per la gestione delle password, costruita con Python e Streamlit. Questo progetto è inteso principalmente per scopi didattici e dimostrativi.

**Lingua:** Italiano

---

## 📜 Descrizione

Password Manager Pro ti permette di memorizzare in modo sicuro le tue credenziali (username e password) per vari servizi. Utilizza una master password per proteggere l'accesso e tecniche di crittografia robuste per la conservazione dei dati. L'interfaccia utente è interamente basata su web grazie a Streamlit.

⚠️ **Disclaimer Importante sulla Sicurezza:**
Questo password manager è stato sviluppato come progetto didattico. Sebbene implementi diverse funzionalità di sicurezza (hashing della master password, KDF, crittografia dei dati), **NON è raccomandato per l'uso con password reali, critiche o sensibili in un ambiente di produzione senza una revisione approfondita della sicurezza da parte di esperti e ulteriori meccanismi di protezione.** Per la gestione di password importanti, considera sempre l'utilizzo di soluzioni password manager consolidate, auditate professionalmente e open source.

---

## ✨ Funzionalità Implementate

* **Autenticazione Robusta con Master Password:**
    * Setup iniziale di una master password.
    * Hashing della master password utilizzando `bcrypt` per una memorizzazione sicura del digest.
* **Derivazione della Chiave di Crittografia (KDF):**
    * La chiave utilizzata per criptare e decriptare le password dei servizi è derivata dalla master password e da un "salt" unico utilizzando PBKDF2HMAC (`hashlib`).
    * Questo elimina la necessità di un file chiave separato per la crittografia dei dati, legandola direttamente alla master password.
* **Crittografia dei Dati:**
    * Le password dei singoli servizi sono criptate utilizzando la crittografia simmetrica Fernet (dalla libreria `cryptography`) prima di essere salvate.
* **Gestione delle Credenziali:**
    * **Aggiunta:** Inserimento di nuove credenziali (servizio, username, password, segreto TOTP opzionale).
    * **Visualizzazione:** Elenco di tutte le credenziali salvate, con badge visivi (⚠️ Debole, 🔁 Riutilizzata, 🗓️ Anziana) e possibilità di mostrare/nascondere/copiare le password.
    * **Modifica:** Modifica diretta di username e password per credenziali esistenti.
    * **Eliminazione:** Rimozione delle credenziali con conferma esplicita a due passaggi per evitare cancellazioni accidentali.
    * **Ricerca/Filtro/Ordinamento:** Campo di ricerca per filtrare le credenziali per nome del servizio, con ordinamento per nome, data di modifica o robustezza.
* **Generatore di Password Casuali Avanzato:**
    * Generazione di password robuste direttamente dall'interfaccia.
    * Lunghezza della password personalizzabile.
    * Opzioni per includere lettere maiuscole, minuscole, numeri e simboli.
    * Opzione per escludere caratteri ambigui (es. `I, l, 1, O, 0`).
* **Autenticazione a Due Fattori (TOTP):**
    * Generazione del codice 2FA corrente per i servizi che hanno un segreto TOTP salvato, con copia rapida e conto alla rovescia visivo.
* **Indicatore di Robustezza della Password:**
    * Feedback in tempo reale (testo e barra colorata) sulla robustezza della password mentre viene digitata (nel form di aggiunta, modifica e durante il setup della master password) utilizzando la libreria `zxcvbn-python`.
    * Indicazione della robustezza anche per le password generate.
* **Import/Export del Database Password:**
    * **Esportazione:** Possibilità di scaricare un backup dell'intero database di password (le password rimangono criptate nel file esportato) in formato JSON.
    * **Importazione:** Caricamento di un file di backup JSON con validazione della struttura e conferma esplicita prima di sovrascrivere il database esistente.
* **Sicurezza della Sessione:**
    * Blocco del login dopo tentativi falliti ripetuti e disconnessione automatica per inattività.
* **Interfaccia Utente Web:**
    * Interfaccia utente intuitiva e reattiva costruita con Streamlit, con schermate di login/setup centrate, dashboard di sicurezza con metriche riassuntive e pagina Utility organizzata in tab.

---

## 🛠️ Stack Tecnologico e Requisiti

* **Python** (versione 3.8+ raccomandata)
* **Librerie Python:**
    * `streamlit`: Per l'interfaccia utente web.
    * `cryptography`: Per la crittografia Fernet.
    * `bcrypt`: Per l'hashing della master password.
    * `zxcvbn-python`: Per la valutazione della robustezza delle password.
    * `pyotp`: Per la generazione dei codici 2FA (TOTP).
    * Librerie standard: `json`, `base64`, `random`, `string`, `os`, `hashlib`.

---

## 🚀 Setup e Installazione

1.  **Clona/Scarica il Repository:**
    Se il progetto fosse su GitHub:
    ```bash
    git clone [https://github.com/TUO_UTENTE/NOME_REPOSITORY.git](https://github.com/TUO_UTENTE/NOME_REPOSITORY.git)
    cd NOME_REPOSITORY
    ```
    Altrimenti, scarica i file sorgente in una cartella sul tuo computer.

2.  **Crea un Ambiente Virtuale (Raccomandato):**
    ```bash
    python -m venv .venv
    source .venv/bin/activate  # Su Windows: .venv\Scripts\activate
    ```

3.  **Installa le Dipendenze:**
    Il file `requirements.txt` è già incluso nel repository:
    ```bash
    pip install -r requirements.txt
    ```

---

## ▶️ Esecuzione dell'Applicazione

Una volta completato il setup e con l'ambiente virtuale attivato, esegui il seguente comando dalla cartella principale del progetto:

```bash
streamlit run ps_manager_app.py
```

---

## 🧪 Test

La logica principale (`PasswordManager` e le funzioni helper) è isolata nel modulo `password_manager.py` ed è coperta da test unitari con `pytest`:

```bash
pip install pytest
pytest tests/
```

---

## 🌐 Interfaccia alternativa: webapp React + FastAPI

Oltre all'interfaccia Streamlit, il progetto include una **seconda interfaccia**, opzionale e indipendente, nella cartella [`webapp/`](webapp/): un frontend React/TypeScript con look moderno (Tailwind, componenti in stile shadcn/ui) e un backend FastAPI, entrambi pensati per uso locale (il backend ascolta solo su `127.0.0.1`).

Le due interfacce sono equivalenti dal punto di vista funzionale e operano sullo **stesso vault** (`passwords.json`, `master_pwd.hash`, `kdf.salt` nella radice del repository): riusano entrambe `password_manager.py` senza duplicare la logica di dominio. Puoi usare l'una o l'altra indifferentemente (non contemporaneamente sullo stesso file di lock del processo, ma sugli stessi dati).

Per l'avvio e i dettagli architetturali vedi [`webapp/README.md`](webapp/README.md).