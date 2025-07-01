import streamlit as st
import json
import os
import bcrypt
import base64
import hashlib
import random
import string
from cryptography.fernet import Fernet
from zxcvbn import zxcvbn
from typing import Dict, Any, Optional, Tuple

# --- CONFIGURAZIONE INIZIALE STREAMLIT ---
st.set_page_config(page_title="Password Manager Pro", layout="wide", initial_sidebar_state="expanded")

# --- COSTANTI DI CONFIGURAZIONE ---
PASSWORDS_FILE = "passwords.json"
MASTER_HASH_FILE = "master_pwd.hash"
KDF_SALT_FILE = "kdf.salt"
PBKDF2_ITERATIONS = 600000  # Aumentato per maggiore sicurezza (raccomandazione OWASP)
SYMBOLS = r"""!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~"""
AMBIGUOUS_CHARACTERS = "Il1O0|'`"


# --- CLASSE DI GESTIONE LOGICA ---
class PasswordManager:
    """
    Incapsula tutta la logica di gestione delle password:
    - Gestione file (hash, salt, database)
    - Operazioni crittografiche (hashing, derivazione chiave, cifratura)
    - Operazioni CRUD sulle credenziali.
    """

    def __init__(self, hash_file: str, salt_file: str, db_file: str):
        self.hash_file = hash_file
        self.salt_file = salt_file
        self.db_file = db_file
        self.cipher_suite: Optional[Fernet] = None

    # --- Gestione Master Password & Salt ---
    def master_hash_exists(self) -> bool:
        return os.path.exists(self.hash_file)

    def load_master_hash(self) -> Optional[bytes]:
        if not self.master_hash_exists(): return None
        with open(self.hash_file, "rb") as f:
            return f.read()

    def set_master_hash(self, password: str) -> None:
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
        with open(self.hash_file, "wb") as f:
            f.write(hashed_password)

    def verify_master_password(self, password: str) -> bool:
        stored_hash = self.load_master_hash()
        if not password or not stored_hash: return False
        try:
            return bcrypt.checkpw(password.encode('utf-8'), stored_hash)
        except ValueError:
            return False

    def load_kdf_salt(self) -> Optional[bytes]:
        if not os.path.exists(self.salt_file): return None
        with open(self.salt_file, "rb") as f:
            return f.read()

    def generate_and_save_kdf_salt(self) -> bytes:
        salt = os.urandom(16)
        with open(self.salt_file, "wb") as f:
            f.write(salt)
        return salt

    # --- Gestione Chiave di Crittografia ---
    def derive_and_set_cipher(self, master_password: str, salt: bytes) -> None:
        key = hashlib.pbkdf2_hmac('sha256', master_password.encode('utf-8'), salt, PBKDF2_ITERATIONS, dklen=32)
        fernet_key = base64.urlsafe_b64encode(key)
        self.cipher_suite = Fernet(fernet_key)

    # --- Gestione Database Password (Criptato) ---
    def load_encrypted_db(self) -> Dict[str, Any]:
        try:
            with open(self.db_file, "r") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def save_encrypted_db(self, data: Dict[str, Any]) -> None:
        with open(self.db_file, "w") as f:
            json.dump(data, f, indent=4)

    def get_decrypted_passwords(self) -> Optional[Dict[str, Dict[str, str]]]:
        if not self.cipher_suite: return None

        encrypted_db = self.load_encrypted_db()
        decrypted_data = {}
        for service, credentials in encrypted_db.items():
            try:
                decrypted_password = self.cipher_suite.decrypt(credentials['password_criptata'].encode()).decode()
                decrypted_data[service] = {
                    "username": credentials['username'],
                    "password": decrypted_password
                }
            except Exception:
                decrypted_data[service] = {
                    "username": credentials['username'],
                    "password": "ERRORE DI DECRIPTAZIONE"
                }
        return decrypted_data

    def add_credential(self, service: str, username: str, password: str) -> bool:
        if not self.cipher_suite: return False

        encrypted_password = self.cipher_suite.encrypt(password.encode()).decode()
        db = self.load_encrypted_db()
        db[service] = {"username": username, "password_criptata": encrypted_password}
        self.save_encrypted_db(db)
        return True

    def update_credential(self, service: str, new_username: str, new_password: str) -> bool:
        return self.add_credential(service, new_username, new_password)

    def delete_credential(self, service: str) -> None:
        db = self.load_encrypted_db()
        if service in db:
            del db[service]
            self.save_encrypted_db(db)


# --- FUNZIONI HELPER UI ---
def get_password_strength_feedback(password: str) -> Tuple[str, str, int, str]:
    if not password: return "", "", 0, "grey"
    results = zxcvbn(password)
    score = results['score']
    feedback_text = results.get('feedback', {}).get('warning', '')
    suggestions = " ".join(results.get('feedback', {}).get('suggestions', []))
    full_feedback = f"{feedback_text} {suggestions}".strip()

    strength_map = {
        0: ("Pessima 😱", "red"), 1: ("Debole 😟", "orange"), 2: ("Discreta 🤔", "yellow"),
        3: ("Buona 😊", "green"), 4: ("Ottima! 💪", "darkgreen")
    }
    strength_text, color = strength_map.get(score, ("Sconosciuta", "grey"))
    return strength_text, full_feedback, score, color


def generate_random_password(length: int, use_upper: bool, use_lower: bool, use_digits: bool, use_symbols: bool,
                             exclude_ambiguous: bool) -> str:
    char_pool, guaranteed_chars = [], []

    def filter_ambiguous(char_set: str) -> str:
        return "".join(c for c in char_set if c not in AMBIGUOUS_CHARACTERS) if exclude_ambiguous else char_set

    sets = {
        "upper": (use_upper, filter_ambiguous(string.ascii_uppercase)),
        "lower": (use_lower, filter_ambiguous(string.ascii_lowercase)),
        "digits": (use_digits, filter_ambiguous(string.digits)),
        "symbols": (use_symbols, filter_ambiguous(SYMBOLS))
    }

    for use_flag, char_set in sets.values():
        if use_flag and char_set:
            char_pool.extend(list(char_set))
            guaranteed_chars.append(random.choice(char_set))

    if not char_pool: return ""

    remaining_len = length - len(guaranteed_chars)
    if remaining_len < 0:
        random.shuffle(guaranteed_chars)
        return "".join(guaranteed_chars[:length])

    password_fill = random.choices(char_pool, k=remaining_len)
    final_password_list = guaranteed_chars + password_fill
    random.shuffle(final_password_list)
    return "".join(final_password_list)


def display_strength_bar(password: str):
    """Mostra un indicatore di robustezza per la password data."""
    if password:
        strength_text, feedback, _, color = get_password_strength_feedback(password)
        st.markdown(
            f"**Robustezza:** <span style='color:{color}; font-weight:bold;'>{strength_text}</span>. *{feedback}*",
            unsafe_allow_html=True)


# --- INTERFACCIA PRINCIPALE STREAMLIT ---
def main():
    st.title("🔑 Password Manager Pro")
    st.caption(
        "⚠️ Questo è un progetto a scopo didattico. Per dati critici, considera soluzioni professionali e auditate.")

    manager = PasswordManager(MASTER_HASH_FILE, KDF_SALT_FILE, PASSWORDS_FILE)

    # --- Inizializzazione Session State ---
    if "authenticated" not in st.session_state:
        st.session_state.authenticated = False
    if "editing_service" not in st.session_state:
        st.session_state.editing_service = None  # Semplifica la logica di modifica

    # 1. SETUP INIZIALE (se non esiste la master password)
    if not manager.master_hash_exists():
        st.subheader("🔑 Imposta la tua Master Password")
        st.info("Benvenuto! Crea una password principale robusta. Sarà l'unica che dovrai ricordare.")

        with st.form("setup_form"):
            new_pwd = st.text_input("Nuova Master Password", type="password")
            confirm_pwd = st.text_input("Conferma Master Password", type="password")

            display_strength_bar(new_pwd)
            submitted = st.form_submit_button("Imposta e Accedi")

            if submitted:
                _, _, score, _ = get_password_strength_feedback(new_pwd)
                if not new_pwd or not confirm_pwd:
                    st.error("Entrambi i campi sono obbligatori.")
                elif len(new_pwd) < 12:
                    st.error("La Master Password deve essere di almeno 12 caratteri.")
                elif new_pwd != confirm_pwd:
                    st.error("Le password non coincidono.")
                elif score < 3:
                    st.warning("Password debole. Scegli una combinazione più robusta e lunga.")
                else:
                    manager.set_master_hash(new_pwd)
                    salt = manager.generate_and_save_kdf_salt()
                    st.session_state.master_password_cache = new_pwd
                    st.session_state.authenticated = True
                    st.success("Master Password impostata! Accesso eseguito.")
                    st.rerun()

    # 2. LOGIN (se esiste la master password ma l'utente non è autenticato)
    elif not st.session_state.authenticated:
        st.subheader("Login")
        with st.form("login_form"):
            master_pwd_input = st.text_input("Inserisci la Master Password", type="password")
            submitted = st.form_submit_button("Sblocca")

            if submitted:
                if manager.verify_master_password(master_pwd_input):
                    st.session_state.master_password_cache = master_pwd_input
                    st.session_state.authenticated = True
                    st.success("Accesso effettuato!")
                    st.rerun()
                else:
                    st.error("Master Password errata.")

    # 3. APP PRINCIPALE (se l'utente è autenticato)
    else:
        kdf_salt = manager.load_kdf_salt()
        if not kdf_salt or 'master_password_cache' not in st.session_state:
            st.error("Errore di sessione. Eseguire nuovamente il login.")
            st.session_state.authenticated = False
            st.rerun()
            return

        manager.derive_and_set_cipher(st.session_state.master_password_cache, kdf_salt)

        # --- SIDEBAR ---
        st.sidebar.success("✅ Accesso Eseguito")
        if st.sidebar.button("Blocca App", use_container_width=True, type="primary"):
            for key in list(st.session_state.keys()):
                del st.session_state[key]
            st.rerun()

        st.sidebar.markdown("---")
        menu_options = ["👀 Visualizza/Modifica", "➕ Aggiungi Nuova", "⚙️ Utility"]
        scelta = st.sidebar.radio("Menu", menu_options)

        decrypted_passwords = manager.get_decrypted_passwords()
        if decrypted_passwords is None:
            st.error("Impossibile decriptare i dati. La sessione potrebbe essere scaduta.")
            st.stop()

        # --- SEZIONE VISUALIZZA/MODIFICA/ELIMINA ---
        if scelta == "👀 Visualizza/Modifica":
            st.header("Visualizza, Modifica ed Elimina Credenziali")
            search_term = st.text_input("Cerca per Servizio", placeholder="Es. Google, Amazon...").lower()

            filtered_creds = {s: d for s, d in decrypted_passwords.items() if
                              search_term in s.lower()} if search_term else decrypted_passwords

            if not filtered_creds:
                st.info(
                    "Nessuna credenziale trovata." if not search_term else f"Nessuna credenziale trovata per '{search_term}'.")

            for service, data in filtered_creds.items():
                if st.session_state.editing_service == service:
                    with st.expander(f"📝 Modifica: **{service}**", expanded=True):
                        with st.form(key=f"edit_{service}"):
                            new_username = st.text_input("Username/Email", value=data['username'])
                            new_password = st.text_input("Password", value=data['password'], type="password")
                            display_strength_bar(new_password)

                            c1, c2 = st.columns(2)
                            if c1.form_submit_button("Salva Modifiche", use_container_width=True, type="primary"):
                                manager.update_credential(service, new_username, new_password)
                                st.success(f"Credenziale per '{service}' aggiornata.")
                                st.session_state.editing_service = None
                                st.rerun()

                            if c2.form_submit_button("Annulla", use_container_width=True):
                                st.session_state.editing_service = None
                                st.rerun()
                else:
                    with st.expander(f"🔑 {service}"):
                        st.text_input("Username/Email", value=data['username'], disabled=True,
                                      key=f"disp_user_{service}")
                        st.text_input("Password", value="∗∗∗∗∗∗∗∗∗", disabled=True, key=f"disp_pwd_{service}")

                        c1, c2, c3 = st.columns(3)
                        if c1.button("Mostra Password", key=f"show_{service}"):
                            st.info(f"**Password per {service}:** `{data['password']}`")
                        if c2.button("Modifica", key=f"edit_{service}"):
                            st.session_state.editing_service = service
                            st.rerun()
                        if c3.button("🗑️ Elimina", key=f"del_{service}", type="primary"):
                            manager.delete_credential(service)
                            st.success(f"Credenziale per '{service}' eliminata.")
                            st.rerun()

        # --- SEZIONE AGGIUNGI NUOVA ---
        elif scelta == "➕ Aggiungi Nuova":
            st.header("Aggiungi Nuova Credenziale")

            with st.expander("✨ Generatore Password", expanded=False):
                g1, g2 = st.columns(2)
                length = g1.slider("Lunghezza", 8, 128, 20)
                exclude_ambiguous = g2.checkbox("Escludi caratteri ambigui (Il1O0|')", True)

                g_opts = st.columns(4)
                use_upper = g_opts[0].checkbox("Maiuscole (A-Z)", True)
                use_lower = g_opts[1].checkbox("Minuscole (a-z)", True)
                use_digits = g_opts[2].checkbox("Numeri (0-9)", True)
                use_symbols = g_opts[3].checkbox("Simboli (@#$%)", True)

                if st.button("Genera e usa password"):
                    generated_pwd = generate_random_password(length, use_upper, use_lower, use_digits, use_symbols,
                                                             exclude_ambiguous)
                    st.session_state.add_password_value = generated_pwd
                    st.code(generated_pwd)

            with st.form("add_credential_form"):
                service = st.text_input("Servizio/Sito Web")
                username = st.text_input("Username/Email")
                password = st.text_input("Password", type="password",
                                         value=st.session_state.get("add_password_value", ""))

                display_strength_bar(password)

                submitted = st.form_submit_button("Salva Credenziale", use_container_width=True, type="primary")
                if submitted:
                    if not all([service, username, password]):
                        st.error("Tutti i campi sono obbligatori.")
                    elif service in decrypted_passwords:
                        st.error(
                            f"Un servizio con nome '{service}' esiste già. Usa un nome diverso o modifica quello esistente.")
                    else:
                        if manager.add_credential(service, username, password):
                            st.success(f"Credenziale per '{service}' aggiunta con successo!")
                            if 'add_password_value' in st.session_state:
                                del st.session_state.add_password_value
                            st.rerun()
                        else:
                            st.error("Errore durante il salvataggio della credenziale.")

        # --- SEZIONE UTILITY ---
        elif scelta == "⚙️ Utility":
            st.header("Utility Database (Import/Export)")
            st.warning("Assicurati che il file importato sia stato criptato con la stessa Master Password.")

            st.subheader("📤 Esporta Database")
            db_data = manager.load_encrypted_db()
            if not db_data:
                st.info("Nessun dato da esportare.")
            else:
                st.download_button(
                    label="Scarica Backup Criptato (.json)",
                    data=json.dumps(db_data, indent=4),
                    file_name="password_manager_backup.json",
                    mime="application/json"
                )

            st.subheader("📥 Importa Database")
            uploaded_file = st.file_uploader("Carica un file di backup (.json)", type="json")
            if uploaded_file:
                try:
                    imported_data = json.load(uploaded_file)
                    st.success(f"File '{uploaded_file.name}' caricato con {len(imported_data)} voci.")

                    if st.button("Sostituisci Database con l'Importazione", type="primary"):
                        manager.save_encrypted_db(imported_data)
                        st.success("Database importato con successo!")
                        st.rerun()
                except Exception as e:
                    st.error(f"Errore durante l'importazione: {e}")


if __name__ == "__main__":
    main()