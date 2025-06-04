import streamlit as st
import json
from cryptography.fernet import Fernet
import base64
import random
import string
import bcrypt  # Per l'hashing della master password
import os
import hashlib  # Per PBKDF2HMAC (KDF)

# PRIMO COMANDO STREAMLIT DEVE ESSERE QUESTO:
st.set_page_config(page_title="Password Manager KDF", layout="centered")

# --- Costanti ---
# KEY_FILE = "secret.key" # RIMOSSO - Non più necessario
PASSWORDS_FILE = "passwords.json"
MASTER_HASH_FILE = "master_pwd.hash"
KDF_SALT_FILE = "kdf.salt"  # Nuovo file per il salt della KDF
PBKDF2_ITERATIONS = 250000  # Numero di iterazioni per PBKDF2 (più alto è, più sicuro ma più lento)


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
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(plain_password.encode('utf-8'), salt)
    with open(MASTER_HASH_FILE, "wb") as f: f.write(hashed_password)


def load_master_password_hash():
    try:
        with open(MASTER_HASH_FILE, "rb") as f:
            return f.read()
    except FileNotFoundError:
        return None


def verifica_master_password_con_hash(plain_password, stored_hash_bytes):
    if not plain_password or not stored_hash_bytes: return False
    try:
        return bcrypt.checkpw(plain_password.encode('utf-8'), stored_hash_bytes)
    except ValueError:  # Può accadere se stored_hash_bytes non è un hash bcrypt valido
        return False


# --- Gestione KDF e Chiave di Crittografia Dati ---
def generate_and_save_kdf_salt():
    """Genera un nuovo salt per KDF e lo salva."""
    salt = os.urandom(16)  # 16 bytes di salt casuale
    with open(KDF_SALT_FILE, "wb") as f:
        f.write(salt)
    return salt


def load_kdf_salt():
    """Carica il salt KDF dal file."""
    try:
        with open(KDF_SALT_FILE, "rb") as f:
            return f.read()
    except FileNotFoundError:
        return None


def derive_encryption_key(master_password_str, salt_bytes):
    """Deriva una chiave di crittografia usando PBKDF2HMAC dalla master password e dal salt."""
    if not master_password_str or not salt_bytes:
        raise ValueError("Master password e salt non possono essere vuoti per la derivazione della chiave.")

    # PBKDF2HMAC necessita di password e salt come bytes
    password_bytes = master_password_str.encode('utf-8')

    # Deriva la chiave grezza
    # Fernet richiede una chiave di 32 byte
    derived_key_raw = hashlib.pbkdf2_hmac(
        'sha256',  # Algoritmo di hash
        password_bytes,
        salt_bytes,
        PBKDF2_ITERATIONS,
        dklen=32  # Lunghezza della chiave desiderata in byte per Fernet
    )
    # Fernet richiede una chiave codificata in base64 URL-safe
    fernet_key = base64.urlsafe_b64encode(derived_key_raw)
    return fernet_key


def get_cipher_suite_kdf():
    """Ottiene la cipher suite usando la chiave Fernet derivata memorizzata in session_state."""
    if "derived_fernet_key" not in st.session_state or not st.session_state.derived_fernet_key:
        st.error("Chiave di crittografia non disponibile in sessione. Eseguire il login.")
        return None
    try:
        return Fernet(st.session_state.derived_fernet_key)
    except Exception as e:
        st.error(f"Errore nell'inizializzare la cipher suite con la chiave derivata: {e}")
        return None


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
    cs = get_cipher_suite_kdf()
    if not cs: return None  # Errore già gestito da get_cipher_suite_kdf
    return cs.encrypt(messaggio_bytes)


def decripta_messaggio(messaggio_criptato_bytes):
    cs = get_cipher_suite_kdf()
    if not cs: return None  # Errore già gestito da get_cipher_suite_kdf
    try:
        return cs.decrypt(messaggio_criptato_bytes)
    except Exception as e:  # cryptography.fernet.InvalidToken o altri
        st.error(
            f"Errore durante la decriptazione: {e}. La master password potrebbe essere errata (se la chiave è stata derivata male) o i dati corrotti.")
        return None


# --- Interfaccia Streamlit ---
st.title("🔑 Password Manager KDF")
st.caption("⚠️ Attenzione: Questo è un esempio didattico. Per uso produttivo, considera soluzioni auditate.")

# --- Logica di Autenticazione e Setup ---
stored_master_hash = load_master_password_hash()
kdf_salt = load_kdf_salt()  # Carica il salt KDF all'avvio

if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
if "derived_fernet_key" not in st.session_state:  # Assicura che esista la chiave in session_state
    st.session_state.derived_fernet_key = None

if not stored_master_hash:  # --- MODALITÀ SETUP MASTER PASSWORD ---
    st.subheader("🔑 Imposta la tua Master Password")
    st.info("Benvenuto! Configura la tua master password. Questa password cripterà i tuoi dati.")

    with st.form("setup_master_form"):
        new_master_pwd = st.text_input("Nuova Master Password:", type="password", key="new_master_setup")
        confirm_master_pwd = st.text_input("Conferma Master Password:", type="password", key="confirm_master_setup")
        submitted_setup = st.form_submit_button("Imposta e Accedi")

        if submitted_setup:
            if not new_master_pwd or not confirm_master_pwd:
                st.error("Entrambi i campi sono obbligatori.")
            elif len(new_master_pwd) < 10:
                st.error("La master password deve essere di almeno 10 caratteri.")
            elif new_master_pwd != confirm_master_pwd:
                st.error("Le password non coincidono.")
            else:
                try:
                    set_master_password_hash(new_master_pwd)  # Salva l'hash della master password
                    current_kdf_salt = generate_and_save_kdf_salt()  # Genera e salva il salt KDF

                    # Deriva e memorizza la chiave Fernet per la sessione corrente
                    fernet_key_for_session = derive_encryption_key(new_master_pwd, current_kdf_salt)
                    st.session_state.derived_fernet_key = fernet_key_for_session

                    st.session_state.authenticated = True
                    st.success(
                        "Master password impostata e chiave di crittografia derivata con successo! Accesso effettuato.")
                    st.rerun()
                except Exception as e:
                    st.error(f"Errore durante l'impostazione della master password o derivazione chiave: {e}")
    st.stop()

elif not st.session_state.authenticated:  # --- MODALITÀ LOGIN ---
    st.subheader("Login")
    master_password_input = st.text_input("Inserisci la Master Password:", type="password", key="master_pwd_login")
    if st.button("Sblocca", key="unlock_btn"):
        if not kdf_salt:  # Controllo di coerenza: il salt dovrebbe esistere se l'hash esiste
            st.error(
                "Errore critico: File KDF salt mancante. Impossibile procedere. Potrebbe essere necessario resettare l'applicazione.")
        elif verifica_master_password_con_hash(master_password_input, stored_master_hash):
            try:
                # Deriva e memorizza la chiave Fernet per la sessione corrente
                fernet_key_for_session = derive_encryption_key(master_password_input, kdf_salt)
                st.session_state.derived_fernet_key = fernet_key_for_session

                st.session_state.authenticated = True
                st.success("Accesso effettuato!")
                st.rerun()
            except ValueError as ve:  # Errore da derive_encryption_key
                st.error(f"Errore durante la derivazione della chiave: {ve}")
            except Exception as e:
                st.error(f"Errore imprevisto durante il login o la derivazione chiave: {e}")
        else:
            st.error("Master Password errata.")
    st.stop()

# --- SEZIONE AUTENTICATA DELL'APP (il resto del codice rimane per lo più invariato) ---
st.sidebar.success("Accesso effettuato!")
if st.sidebar.button("Blocca App", key="lock_app_btn"):
    st.session_state.authenticated = False
    st.session_state.derived_fernet_key = None  # Pulisce la chiave derivata dalla sessione
    if 'master_pwd_login' in st.session_state: del st.session_state['master_pwd_login']
    st.rerun()

st.header("Gestione Password")
menu = ["➕ Aggiungi Nuova Password", "👀 Visualizza Password", "🗑️ Elimina Password"]
scelta = st.sidebar.selectbox("Menu", menu)
passwords_criptate_db = carica_passwords_criptate()

# ... (Le sezioni "Aggiungi", "Visualizza", "Elimina" rimangono sostanzialmente le stesse,
#      poiché ora usano cripta_messaggio e decripta_messaggio che a loro volta
#      usano get_cipher_suite_kdf() con la chiave derivata.)

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
                encrypted_pass_bytes = cripta_messaggio(nuova_password.encode())
                if encrypted_pass_bytes:  # Verifica che la crittografia sia andata a buon fine
                    passwords_criptate_db[servizio] = {"username": username,
                                                       "password_criptata": encrypted_pass_bytes.decode()}
                    salva_passwords_criptate(passwords_criptate_db)
                    st.success(f"Credenziale per '{servizio}' aggiunta/aggiornata!")
                    st.session_state.generated_password_value_display = ""
                # else: l'errore è già mostrato da cripta_messaggio
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

                show_pwd_key = f"show_pwd_{servizio_idx}"
                if show_pwd_key not in st.session_state: st.session_state[show_pwd_key] = False
                if st.button(f"Mostra/Nascondi Password per {servizio}", key=f"btn_show_{servizio_idx}"):
                    st.session_state[show_pwd_key] = not st.session_state[show_pwd_key]

                if st.session_state[show_pwd_key]:
                    password_decriptata_bytes = decripta_messaggio(dati['password_criptata'].encode())
                    if password_decriptata_bytes:
                        st.text_input("Password:", value=password_decriptata_bytes.decode(), type="default",
                                      disabled=True, key=f"pwd_text_{servizio_idx}_visible")
                    # else: l'errore è già mostrato da decripta_messaggio
                else:
                    st.text_input("Password:", value="∗∗∗∗∗∗∗∗∗∗", type="default", disabled=True,
                                  key=f"pwd_text_{servizio_idx}_hidden")

elif scelta == "🗑️ Elimina Password":
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
st.sidebar.markdown(f"**Salt KDF:** `{KDF_SALT_FILE}`")  # Mostra il file del salt
st.sidebar.markdown(f"**Database Password:** `{PASSWORDS_FILE}`")