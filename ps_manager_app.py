import streamlit as st
import json
from cryptography.fernet import Fernet  # Per la crittografia
import base64  # Per la gestione della chiave
import random  # Per il generatore di password
import string  # Per il generatore di password
import bcrypt  # Per l'hashing della master password
import os  # Per controllare l'esistenza del file hash

# PRIMO COMANDO STREAMLIT DEVE ESSERE QUESTO:
st.set_page_config(page_title="Password Manager Sicuro", layout="centered")  # Titolo leggermente cambiato

# --- Costanti ---
KEY_FILE = "secret.key"  # Ancora usato per la crittografia dei dati, vedi nota sulla KDF per miglioramenti futuri
PASSWORDS_FILE = "passwords.json"
MASTER_HASH_FILE = "master_pwd.hash"  # File per memorizzare l'hash della master password


# --- Funzione Generatore Password ---
def genera_password_casuale(length, use_uppercase, use_lowercase, use_digits, use_symbols):
    character_pool = ""
    guaranteed_chars = []
    if use_uppercase and string.ascii_uppercase: character_pool += string.ascii_uppercase; guaranteed_chars.append(
        random.choice(string.ascii_uppercase))
    if use_lowercase and string.ascii_lowercase: character_pool += string.ascii_lowercase; guaranteed_chars.append(
        random.choice(string.ascii_lowercase))
    if use_digits and string.digits: character_pool += string.digits; guaranteed_chars.append(
        random.choice(string.digits))
    if use_symbols and string.punctuation:
        symbols_to_use = string.punctuation
        character_pool += symbols_to_use;
        guaranteed_chars.append(random.choice(symbols_to_use))

    if not character_pool: return "Errore: Nessun tipo di carattere selezionato."
    if length < len(guaranteed_chars): random.shuffle(guaranteed_chars); return "".join(guaranteed_chars[:length])

    remaining_length = length - len(guaranteed_chars)
    password_fill = [random.choice(character_pool) for _ in range(remaining_length)]
    final_password_list = guaranteed_chars + password_fill
    random.shuffle(final_password_list)
    return "".join(final_password_list)


# --- Gestione Master Password Hashing (bcrypt) ---
def set_master_password_hash(plain_password):
    """Genera l'hash di una password e lo salva."""
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(plain_password.encode('utf-8'), salt)
    with open(MASTER_HASH_FILE, "wb") as f:
        f.write(hashed_password)


def load_master_password_hash():
    """Carica l'hash della master password dal file."""
    try:
        with open(MASTER_HASH_FILE, "rb") as f:
            return f.read()
    except FileNotFoundError:
        return None


def verifica_master_password_con_hash(plain_password, stored_hash_bytes):
    """Verifica una password in chiaro contro un hash memorizzato."""
    if not plain_password or not stored_hash_bytes:
        return False
    return bcrypt.checkpw(plain_password.encode('utf-8'), stored_hash_bytes)


# --- Gestione della Chiave di Crittografia (Ancora separata per ora) ---
def genera_chiave():
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as key_file: key_file.write(key)
    return key


def carica_chiave():
    try:
        with open(KEY_FILE, "rb") as key_file:
            return key_file.read()
    except FileNotFoundError:
        st.warning(
            f"File chiave '{KEY_FILE}' non trovato. Ne verrà generato uno nuovo la prima volta che si salva una password.")
        # La chiave verrà effettivamente generata e salvata solo quando serve la prima volta
        return None  # Non generare subito, ma al primo salvataggio se non esiste


key_bytes = carica_chiave()  # Può essere None inizialmente
cipher_suite = Fernet(key_bytes) if key_bytes else None


def get_cipher_suite():
    """Ottiene o crea la cipher suite. Crea la chiave se non esiste."""
    global key_bytes, cipher_suite
    if not key_bytes:
        st.info(f"Creazione di una nuova chiave di crittografia ({KEY_FILE})...")
        key_bytes = genera_chiave()
        cipher_suite = Fernet(key_bytes)
        st.success(f"Nuova chiave di crittografia '{KEY_FILE}' generata. Conservala con cura!")
    return cipher_suite


# --- Gestione delle Password (JSON) ---
def carica_passwords_criptate():
    try:
        with open(PASSWORDS_FILE, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def salva_passwords_criptate(passwords_criptate):
    with open(PASSWORDS_FILE, "w") as f: json.dump(passwords_criptate, f, indent=4)


def cripta_messaggio(messaggio_bytes):
    cs = get_cipher_suite()
    return cs.encrypt(messaggio_bytes)


def decripta_messaggio(messaggio_criptato_bytes):
    cs = get_cipher_suite()
    if not cs:  # Se la chiave non è ancora stata caricata/generata
        st.error("Chiave di crittografia non disponibile. Impossibile decriptare.")
        return None
    try:
        return cs.decrypt(messaggio_criptato_bytes)
    except Exception as e:
        st.error(f"Errore durante la decriptazione: {e}. La chiave potrebbe essere errata/cambiata o i dati corrotti.")
        return None


# --- Interfaccia Streamlit ---
st.title("🔑 Password Manager Sicuro")
st.caption("⚠️ Attenzione: Questo è un esempio didattico. Per uso produttivo, considera soluzioni auditate.")

# --- Logica di Autenticazione e Setup ---
stored_master_hash = load_master_password_hash()

if "authenticated" not in st.session_state:
    st.session_state.authenticated = False

if not stored_master_hash:  # --- MODALITÀ SETUP MASTER PASSWORD ---
    st.subheader("🔑 Imposta la tua Master Password")
    st.info(
        "Benvenuto! Sembra essere il primo avvio o la master password non è stata ancora impostata. Scegli una password robusta e unica. Questa password sarà usata per proteggere l'accesso al tuo gestore di password.")

    with st.form("setup_master_form"):
        new_master_pwd = st.text_input("Nuova Master Password:", type="password", key="new_master_setup")
        confirm_master_pwd = st.text_input("Conferma Master Password:", type="password", key="confirm_master_setup")
        submitted_setup = st.form_submit_button("Imposta e Accedi")

        if submitted_setup:
            if not new_master_pwd or not confirm_master_pwd:
                st.error("Entrambi i campi sono obbligatori.")
            elif len(new_master_pwd) < 10:  # Aumentato il requisito minimo
                st.error("La master password deve essere di almeno 10 caratteri per una maggiore sicurezza.")
            elif new_master_pwd != confirm_master_pwd:
                st.error("Le password non coincidono.")
            else:
                try:
                    set_master_password_hash(new_master_pwd)
                    st.session_state.authenticated = True
                    # Assicura che la chiave di crittografia sia pronta
                    get_cipher_suite()
                    st.success("Master password impostata con successo! Accesso effettuato.")
                    st.rerun()
                except Exception as e:
                    st.error(f"Errore durante l'impostazione della master password: {e}")
    st.stop()  # Ferma l'esecuzione dello script qui se siamo in setup

elif not st.session_state.authenticated:  # --- MODALITÀ LOGIN ---
    st.subheader("Login")
    master_password_input = st.text_input("Inserisci la Master Password:", type="password", key="master_pwd_login")
    if st.button("Sblocca", key="unlock_btn"):
        if verifica_master_password_con_hash(master_password_input, stored_master_hash):
            st.session_state.authenticated = True
            st.success("Accesso effettuato!")
            st.rerun()
        else:
            st.error("Master Password errata.")
    st.stop()  # Ferma l'esecuzione se non autenticato

# --- SEZIONE AUTENTICATA DELL'APP ---
st.sidebar.success("Accesso effettuato!")
if st.sidebar.button("Blocca App", key="lock_app_btn"):
    st.session_state.authenticated = False
    if 'master_pwd_login' in st.session_state: del st.session_state['master_pwd_login']
    st.rerun()

st.header("Gestione Password")
menu = ["➕ Aggiungi Nuova Password", "👀 Visualizza Password", "🗑️ Elimina Password"]
scelta = st.sidebar.selectbox("Menu", menu)
passwords_criptate_db = carica_passwords_criptate()

if scelta == "➕ Aggiungi Nuova Password":
    st.subheader("Aggiungi Nuova Credenziale")
    st.markdown("---")
    st.markdown("### ✨ Generatore Password Casuale")
    pwd_length = st.slider("Lunghezza:", 8, 32, 16, key="pwd_gen_length")
    col1, col2 = st.columns(2)
    with col1:
        use_upper = st.checkbox("Maiuscole", True, key="pwd_gen_upper")
    with col2:
        use_digits = st.checkbox("Numeri", True, key="pwd_gen_digits")
    with col1:
        use_lower = st.checkbox("Minuscole", True, key="pwd_gen_lower")
    with col2:
        use_symbols = st.checkbox("Simboli", True, key="pwd_gen_symbols")

    if "generated_password_value_display" not in st.session_state: st.session_state.generated_password_value_display = ""
    if st.button("Genera Password", key="generate_pwd_btn"):
        if not (use_upper or use_lower or use_digits or use_symbols):
            st.error("Seleziona almeno un tipo di carattere.")
            st.session_state.generated_password_value_display = ""
        else:
            st.session_state.generated_password_value_display = genera_password_casuale(pwd_length, use_upper,
                                                                                        use_lower, use_digits,
                                                                                        use_symbols)
    if st.session_state.generated_password_value_display:
        st.code(st.session_state.generated_password_value_display)
        st.caption("Copia la password e incollala nel campo 'Password' qui sotto.")
    st.markdown("---")

    with st.form("add_form", clear_on_submit=True):
        servizio = st.text_input("Servizio/Sito Web:")
        username = st.text_input("Username/Email:")
        nuova_password = st.text_input("Password:", type="password", help="Puoi incollare qui la password generata.")
        submitted = st.form_submit_button("Salva Credenziale")

        if submitted:
            if servizio and username and nuova_password:
                pass_criptata = cripta_messaggio(nuova_password.encode()).decode()
                passwords_criptate_db[servizio] = {"username": username, "password_criptata": pass_criptata}
                salva_passwords_criptate(passwords_criptate_db)
                st.success(f"Credenziale per '{servizio}' aggiunta/aggiornata!")
                st.session_state.generated_password_value_display = ""
            else:
                st.error("Per favore, compila tutti i campi.")

elif scelta == "👀 Visualizza Password":
    # ... (codice per visualizzare le password, invariato rispetto all'ultima versione, assicurati che usi decripta_messaggio()) ...
    st.subheader("Le Tue Credenziali Salvate")
    if not passwords_criptate_db:
        st.info("Nessuna password salvata al momento.")
    else:
        for servizio_idx, (servizio, dati) in enumerate(passwords_criptate_db.items()):
            with st.expander(f"🔑 {servizio}"):
                st.text(f"Username/Email: {dati['username']}")

                show_pwd_key = f"show_pwd_{servizio_idx}"
                if show_pwd_key not in st.session_state: st.session_state[show_pwd_key] = False
                if st.button(f"Mostra/Nascondi Password per {servizio}", key=f"btn_show_{servizio_idx}"):
                    st.session_state[show_pwd_key] = not st.session_state[show_pwd_key]

                if st.session_state[show_pwd_key]:
                    password_decriptata_bytes = decripta_messaggio(dati['password_criptata'].encode())
                    if password_decriptata_bytes:
                        st.text_input("Password:", value=password_decriptata_bytes.decode(), type="default",
                                      disabled=True, key=f"pwd_text_{servizio_idx}_visible")
                    else:
                        st.error("Impossibile decriptare la password.")  # Errore già mostrato da decripta_messaggio
                else:
                    st.text_input("Password:", value="∗∗∗∗∗∗∗∗∗∗", type="default", disabled=True,
                                  key=f"pwd_text_{servizio_idx}_hidden")

elif scelta == "🗑️ Elimina Password":
    # ... (codice per eliminare le password, invariato rispetto all'ultima versione) ...
    st.subheader("Elimina Credenziale")
    if not passwords_criptate_db:
        st.info("Nessuna password da eliminare.")
    else:
        servizi_disponibili = list(passwords_criptate_db.keys())
        servizio_da_eliminare = st.selectbox("Seleziona il servizio da eliminare:", servizi_disponibili, index=None,
                                             placeholder="Scegli un servizio...")
        if servizio_da_eliminare:
            if st.button(f"Conferma Eliminazione di '{servizio_da_eliminare}'", type="primary"):
                if servizio_da_eliminare in passwords_criptate_db:
                    del passwords_criptate_db[servizio_da_eliminare]
                    salva_passwords_criptate(passwords_criptate_db)
                    st.success(f"Credenziale per '{servizio_da_eliminare}' eliminata!")
                    st.rerun()
                else:
                    st.error("Servizio non trovato.")

st.sidebar.markdown("---")
st.sidebar.markdown(f"**Hash Master Pwd:** `{MASTER_HASH_FILE}`")
st.sidebar.markdown(f"**Chiave Crittografia Dati:** `{KEY_FILE}`")
st.sidebar.markdown(f"**Database Password:** `{PASSWORDS_FILE}`")