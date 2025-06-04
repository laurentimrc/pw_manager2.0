import streamlit as st
import json
from cryptography.fernet import Fernet  # Per la crittografia
import base64  # Per la gestione della chiave

# PRIMO COMANDO STREAMLIT DEVE ESSERE QUESTO:
st.set_page_config(page_title="Password Manager Semplice", layout="centered")

# --- Gestione della Chiave di Crittografia ---
# Idealmente, questa chiave dovrebbe essere gestita in modo più sicuro,
# ad esempio derivata da una master password con un KDF (Key Derivation Function)
# e non memorizzata direttamente nel codice o in un file facilmente accessibile.
# Per questo esempio, la genereremo o caricheremo da un file.

KEY_FILE = "secret.key"


def genera_chiave():
    """Genera una nuova chiave di crittografia e la salva in un file."""
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as key_file:
        key_file.write(key)
    return key


def carica_chiave():
    """Carica la chiave di crittografia dal file."""
    try:
        with open(KEY_FILE, "rb") as key_file:
            key = key_file.read()
        return key
    except FileNotFoundError:
        st.warning(f"File chiave '{KEY_FILE}' non trovato. Ne verrà generato uno nuovo.")
        return genera_chiave()


key = carica_chiave()
cipher_suite = Fernet(key)

# --- Gestione delle Password ---
PASSWORDS_FILE = "passwords.json"


def carica_passwords_criptate():
    """Carica le password criptate dal file JSON."""
    try:
        with open(PASSWORDS_FILE, "r") as f:
            passwords_criptate = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        passwords_criptate = {}
    return passwords_criptate


def salva_passwords_criptate(passwords_criptate):
    """Salva le password criptate nel file JSON."""
    with open(PASSWORDS_FILE, "w") as f:
        json.dump(passwords_criptate, f, indent=4)


def cripta_messaggio(messaggio_bytes):
    """Cripta un messaggio."""
    return cipher_suite.encrypt(messaggio_bytes)


def decripta_messaggio(messaggio_criptato_bytes):
    """Decripta un messaggio."""
    try:
        return cipher_suite.decrypt(messaggio_criptato_bytes)
    except Exception as e:  # cryptography.fernet.InvalidToken
        st.error(f"Errore durante la decriptazione: {e}. La chiave potrebbe essere cambiata o i dati corrotti.")
        return None


# --- Autenticazione Semplificata ---
# In un'applicazione reale, la master password dovrebbe essere hashata
# e confrontata con un hash memorizzato, non memorizzata o confrontata direttamente.
# MASTER_PASSWORD_HASH_PLACEHOLDER = "impostare_una_password_robusta_e_hasharla" # Esempio, da NON usare così

def verifica_master_password(password_inserita):
    """Verifica la master password (MOLTO SEMPLIFICATO)."""
    # Qui dovresti confrontare l'hash della password inserita con un hash memorizzato.
    # Per questo esempio, la confrontiamo direttamente (NON SICURO).
    # In una versione reale, usa bcrypt o Argon2.
    # Per ora, per sbloccare l'app, simuliamo che l'utente debba impostarla la prima volta
    # o inserirla correttamente se già impostata (simulato).

    # Semplifichiamo per il debug: se lo stato master_password_set non esiste,
    # consideriamo la prima password inserita corretta per "impostarla".
    if "master_password_actual" not in st.session_state:
        st.session_state.master_password_actual = password_inserita  # Memorizza (non sicuro!) la password per questo esempio
        st.session_state.authenticated = True
        st.success("Master password 'impostata' per questa sessione. Accesso consentito.")
        return True

    if password_inserita == st.session_state.master_password_actual:
        st.session_state.authenticated = True
        return True
    else:
        st.session_state.authenticated = False
        return False


# --- Interfaccia Streamlit ---
# st.set_page_config è stato spostato all'inizio del file

st.title("🔑 Password Manager Semplice")
st.caption("⚠️ Attenzione: Questo è un esempio didattico e non per uso produttivo con dati sensibili.")

# --- Flusso di Autenticazione ---
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False

if not st.session_state.authenticated:
    st.subheader("Login")
    if "master_password_actual" not in st.session_state:
        st.info(
            "Sembra essere il primo avvio o la master password non è stata ancora impostata in questa sessione. La password che inserisci ora verrà considerata la master password.")
    master_password_input = st.text_input("Inserisci la Master Password:", type="password", key="master_pwd_login")
    if st.button("Sblocca", key="unlock_btn"):
        if verifica_master_password(master_password_input):
            # St.rerun() può causare loop se lo stato non è gestito perfettamente subito dopo.
            # In questo caso, Streamlit dovrebbe rieseguire automaticamente quando lo stato cambia.
            st.success("Accesso effettuato!")  # Fornisce un feedback immediato
            st.experimental_rerun()  # Usa experimental_rerun per forzare il rieseguimento
        else:
            st.error("Master Password errata.")
else:
    st.sidebar.success("Accesso effettuato!")
    if st.sidebar.button("Blocca App", key="lock_app_btn"):
        st.session_state.authenticated = False
        # Cancella le password sensibili dalla sessione se necessario
        if 'master_pwd_login' in st.session_state:
            del st.session_state['master_pwd_login']
        # Non cancellare master_password_actual per permettere il re-login con la stessa password nella sessione
        st.experimental_rerun()

    st.header("Gestione Password")

    menu = ["➕ Aggiungi Nuova Password", "👀 Visualizza Password", "🗑️ Elimina Password"]
    scelta = st.sidebar.selectbox("Menu", menu)

    passwords_criptate_db = carica_passwords_criptate()

    if scelta == "➕ Aggiungi Nuova Password":
        st.subheader("Aggiungi Nuova Credenziale")
        with st.form("add_form", clear_on_submit=True):
            servizio = st.text_input("Servizio/Sito Web:")
            username = st.text_input("Username/Email:")
            nuova_password = st.text_input("Password:", type="password")
            submitted = st.form_submit_button("Salva Credenziale")

            if submitted:
                if servizio and username and nuova_password:
                    if servizio in passwords_criptate_db:
                        # Semplificato: sovrascrive direttamente senza ulteriore conferma qui
                        # Potresti aggiungere un checkbox "Sovrascrivi se esistente" o un popup di conferma
                        pass_criptata = cripta_messaggio(nuova_password.encode()).decode()
                        passwords_criptate_db[servizio] = {"username": username, "password_criptata": pass_criptata}
                        salva_passwords_criptate(passwords_criptate_db)
                        st.success(f"Credenziale per '{servizio}' aggiornata/sovrascritta con successo!")
                    else:
                        pass_criptata = cripta_messaggio(nuova_password.encode()).decode()
                        passwords_criptate_db[servizio] = {"username": username, "password_criptata": pass_criptata}
                        salva_passwords_criptate(passwords_criptate_db)
                        st.success(f"Credenziale per '{servizio}' aggiunta con successo!")
                else:
                    st.error("Per favore, compila tutti i campi.")

    elif scelta == "👀 Visualizza Password":
        st.subheader("Le Tue Credenziali Salvate")
        if not passwords_criptate_db:
            st.info("Nessuna password salvata al momento.")
        else:
            for servizio_idx, (servizio, dati) in enumerate(passwords_criptate_db.items()):
                with st.expander(f"🔑 {servizio}"):
                    st.text(f"Username/Email: {dati['username']}")

                    # Stato per mostrare/nascondere la password
                    show_pwd_key = f"show_pwd_{servizio_idx}"
                    if show_pwd_key not in st.session_state:
                        st.session_state[show_pwd_key] = False

                    if st.button(f"Mostra Password per {servizio}", key=f"btn_show_{servizio_idx}"):
                        st.session_state[show_pwd_key] = not st.session_state[show_pwd_key]  # Toggle

                    if st.session_state[show_pwd_key]:
                        try:
                            password_decriptata_bytes = decripta_messaggio(dati['password_criptata'].encode())
                            if password_decriptata_bytes:
                                st.text_input("Password:", value=password_decriptata_bytes.decode(), type="default",
                                              disabled=True, key=f"pwd_text_{servizio_idx}")
                                # Aggiungere un bottone per copiare negli appunti sarebbe utile qui
                            else:
                                st.error("Impossibile decriptare la password.")
                        except Exception as e:
                            st.error(f"Errore durante la decriptazione per {servizio}: {e}")
                    else:
                        st.text("Password: nascosta")


    elif scelta == "🗑️ Elimina Password":
        st.subheader("Elimina Credenziale")
        if not passwords_criptate_db:
            st.info("Nessuna password da eliminare.")
        else:
            servizi_disponibili = list(passwords_criptate_db.keys())
            # Assicurarsi che l'indice sia valido
            selected_index_delete = st.session_state.get('selected_index_delete', 0 if servizi_disponibili else None)
            if not servizi_disponibili:
                selected_index_delete = None

            servizio_da_eliminare = st.selectbox(
                "Seleziona il servizio da eliminare:",
                options=servizi_disponibili,
                index=selected_index_delete if selected_index_delete is not None and selected_index_delete < len(
                    servizi_disponibili) else 0,  # Gestisce l'indice
                key='selectbox_delete_service',
                placeholder="Scegli un servizio..." if not servizi_disponibili else None
            )

            if servizio_da_eliminare:  # Solo se un servizio è effettivamente selezionato
                if st.button(f"Conferma Eliminazione di '{servizio_da_eliminare}'", type="primary",
                             key=f"delete_confirm_{servizio_da_eliminare}"):
                    if servizio_da_eliminare in passwords_criptate_db:
                        del passwords_criptate_db[servizio_da_eliminare]
                        salva_passwords_criptate(passwords_criptate_db)
                        st.success(f"Credenziale per '{servizio_da_eliminare}' eliminata con successo!")
                        # Resetta l'indice per evitare errori se l'elemento selezionato viene eliminato
                        if 'selected_index_delete' in st.session_state:
                            st.session_state.selected_index_delete = 0
                        st.experimental_rerun()
                    else:
                        st.error("Servizio non trovato (potrebbe essere già stato eliminato).")
            elif not servizi_disponibili:
                st.info("Nessuna password disponibile per l'eliminazione.")

    st.sidebar.markdown("---")
    st.sidebar.markdown(f"**Chiave di crittografia:** `{KEY_FILE}` (gestiscila con cura!)")
    st.sidebar.markdown(f"**Database password:** `{PASSWORDS_FILE}`")

# Per eseguire questo script:
# 1. Salvalo come `password_manager_app.py` (o un nome simile).
# 2. Assicurati di avere le librerie installate: `pip install streamlit cryptography`
# 3. Esegui da terminale: `streamlit run ps_manager_app.py`