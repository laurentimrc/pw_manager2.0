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
from typing import Dict, Any, Optional, Tuple, List
from datetime import datetime, timedelta

# --- CONFIGURAZIONE INIZIALE STREAMLIT ---
st.set_page_config(page_title="Password Manager Pro", layout="wide", initial_sidebar_state="expanded")

# --- COSTANTI DI CONFIGURAZIONE ---
PASSWORDS_FILE = "passwords.json"
MASTER_HASH_FILE = "master_pwd.hash"
KDF_SALT_FILE = "kdf.salt"
PBKDF2_ITERATIONS = 600000
SYMBOLS = r"""!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~"""
AMBIGUOUS_CHARACTERS = "Il1O0|'`"


# --- CLASSE DI GESTIONE LOGICA ---
class PasswordManager:
    """
    Incapsula tutta la logica di gestione delle password.
    """

    def __init__(self, hash_file: str, salt_file: str, db_file: str):
        self.hash_file = hash_file
        self.salt_file = salt_file
        self.db_file = db_file
        self.cipher_suite: Optional[Fernet] = None

    # ... (metodi per hash, salt, KDF rimangono invariati) ...
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

    def derive_and_set_cipher(self, master_password: str, salt: bytes) -> None:
        key = hashlib.pbkdf2_hmac('sha256', master_password.encode('utf-8'), salt, PBKDF2_ITERATIONS, dklen=32)
        fernet_key = base64.urlsafe_b64encode(key)
        self.cipher_suite = Fernet(fernet_key)

    # --- Gestione Database ---
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
                    "password": decrypted_password,
                    "last_updated": credentials.get("last_updated")  # Aggiunto per compatibilità
                }
            except Exception:
                decrypted_data[service] = {"password": "ERRORE DI DECRIPTAZIONE"}
        return decrypted_data

    def add_credential(self, service: str, username: str, password: str) -> bool:
        if not self.cipher_suite: return False

        encrypted_password = self.cipher_suite.encrypt(password.encode()).decode()
        db = self.load_encrypted_db()
        db[service] = {
            "username": username,
            "password_criptata": encrypted_password,
            "last_updated": datetime.now().isoformat()  # NUOVO: Aggiunge timestamp
        }
        self.save_encrypted_db(db)
        return True

    def update_credential(self, service: str, new_username: str, new_password: str) -> bool:
        # L'aggiornamento ora rinnova anche il timestamp
        return self.add_credential(service, new_username, new_password)

    def delete_credential(self, service: str) -> None:
        db = self.load_encrypted_db()
        if service in db:
            del db[service]
            self.save_encrypted_db(db)

    # --- NUOVO METODO: CAMBIO MASTER PASSWORD ---
    def change_master_password(self, old_password: str, new_password: str) -> Tuple[bool, str]:
        """
        Decripta l'intero database con la vecchia password e lo ri-cripta
        con la nuova password. Genera anche un nuovo hash master e un nuovo salt KDF.
        """
        # 1. Verifica che la vecchia password sia corretta
        if not self.verify_master_password(old_password):
            return False, "La vecchia Master Password è errata."

        # --- FASE DI DECRIPTAZIONE (con la vecchia chiave) ---
        old_salt = self.load_kdf_salt()
        if not old_salt:
            return False, "File salt KDF non trovato. Annullamento."

        # Crea un cipher temporaneo con la vecchia password e il vecchio salt
        old_key = hashlib.pbkdf2_hmac('sha256', old_password.encode('utf-8'), old_salt, PBKDF2_ITERATIONS, dklen=32)
        old_fernet_key = base64.urlsafe_b64encode(old_key)
        old_cipher = Fernet(old_fernet_key)

        # Carica il database criptato
        encrypted_db = self.load_encrypted_db()
        decrypted_data_map = {}

        # Decripta tutto in memoria
        for service, credentials in encrypted_db.items():
            try:
                decrypted_password = old_cipher.decrypt(credentials['password_criptata'].encode()).decode()
                decrypted_data_map[service] = {
                    "username": credentials['username'],
                    "password": decrypted_password,
                    "last_updated": credentials.get("last_updated")
                }
            except Exception:
                return False, f"Errore di decriptazione per '{service}'. Annullamento."

        # --- FASE DI RI-CRITTOGRAFIA (con la nuova chiave) ---

        # 1. Imposta il nuovo hash della Master Password
        self.set_master_hash(new_password)

        # 2. Genera e salva un *nuovo* salt KDF
        new_salt = self.generate_and_save_kdf_salt()

        # 3. Crea un nuovo cipher con la nuova password e il nuovo salt
        new_key = hashlib.pbkdf2_hmac('sha256', new_password.encode('utf-8'), new_salt, PBKDF2_ITERATIONS, dklen=32)
        new_fernet_key = base64.urlsafe_b64encode(new_key)
        new_cipher = Fernet(new_fernet_key)

        # 4. Ricostruisci il DB criptato
        new_encrypted_db = {}
        for service, data in decrypted_data_map.items():
            try:
                encrypted_password = new_cipher.encrypt(data['password'].encode()).decode()
                new_encrypted_db[service] = {
                    "username": data['username'],
                    "password_criptata": encrypted_password,
                    "last_updated": data.get("last_updated") or datetime.now().isoformat()
                }
            except Exception as e:
                return False, f"Errore durante la ri-crittografia per '{service}': {e}"

        # 5. Salva il nuovo database
        self.save_encrypted_db(new_encrypted_db)

        # 6. Aggiorna il cipher della sessione corrente
        self.cipher_suite = new_cipher

        return True, "Master Password cambiata con successo!"


# --- (Funzioni Helper UI rimangono invariate) ---
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
    # ... (logica invariata)
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
    if password:
        strength_text, feedback, _, color = get_password_strength_feedback(password)
        st.markdown(
            f"**Robustezza:** <span style='color:{color}; font-weight:bold;'>{strength_text}</span>. *{feedback}*",
            unsafe_allow_html=True)


# --- INTERFACCIA PRINCIPALE STREAMLIT ---
def main():
    st.title("🔑 Password Manager Pro")
    st.caption("⚠️ Questo è un progetto a scopo didatto.")

    manager = PasswordManager(MASTER_HASH_FILE, KDF_SALT_FILE, PASSWORDS_FILE)

    # --- (Logica di Setup e Login invariata) ---
    if "authenticated" not in st.session_state:
        st.session_state.authenticated = False
    if "editing_service" not in st.session_state:
        st.session_state.editing_service = None

    if not manager.master_hash_exists():
        # ... (codice setup invariato)
        st.subheader("🔑 Imposta la tua Master Password")
        st.info("Benvenuto! Crea una password principale robusta.")
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
                    st.warning("Password debole. Scegli una combinazione più robusta.")
                else:
                    manager.set_master_hash(new_pwd)
                    manager.generate_and_save_kdf_salt()
                    st.session_state.master_password_cache = new_pwd
                    st.session_state.authenticated = True
                    st.success("Master Password impostata! Accesso eseguito.")
                    st.rerun()

    elif not st.session_state.authenticated:
        # ... (codice login invariato)
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

    # --- APP PRINCIPALE ---
    else:
        kdf_salt = manager.load_kdf_salt()
        if not kdf_salt or 'master_password_cache' not in st.session_state:
            st.error("Errore di sessione. Eseguire nuovamente il login.")
            st.session_state.authenticated = False
            st.rerun()
            return

        manager.derive_and_set_cipher(st.session_state.master_password_cache, kdf_salt)

        st.sidebar.success("✅ Accesso Eseguito")
        if st.sidebar.button("Blocca App", use_container_width=True, type="primary"):
            for key in list(st.session_state.keys()): del st.session_state[key]
            st.rerun()

        st.sidebar.markdown("---")
        menu_options = ["👀 Visualizza/Modifica", "➕ Aggiungi Nuova", "🛡️ Dashboard Sicurezza", "⚙️ Utility"]
        scelta = st.sidebar.radio("Menu", menu_options)

        decrypted_passwords = manager.get_decrypted_passwords()
        if decrypted_passwords is None:
            st.error("Impossibile decriptare i dati.")
            st.stop()

        # --- (Sezioni Visualizza, Aggiungi sono invariate) ---
        if scelta == "👀 Visualizza/Modifica":
            # ... (codice invariato con il toggle mostra/nascondi)
            st.header("Visualizza, Modifica ed Elimina Credenziali")
            search_term = st.text_input("Cerca per Servizio", placeholder="Es. Google, Amazon...").lower()
            filtered_creds = {s: d for s, d in decrypted_passwords.items() if
                              search_term in s.lower()} if search_term else decrypted_passwords
            if not filtered_creds: st.info("Nessuna credenziale trovata.")
            for service, data in filtered_creds.items():
                show_password_key = f"show_pwd_{service}"
                if show_password_key not in st.session_state: st.session_state[show_password_key] = False
                if st.session_state.editing_service == service:
                    with st.expander(f"📝 Modifica: **{service}**", expanded=True):
                        with st.form(key=f"edit_{service}"):
                            new_username = st.text_input("Username/Email", value=data['username'])
                            new_password = st.text_input("Password", value=data.get('password', ''), type="password")
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
                        st.text_input("Username/Email", value=data['username'], disabled=True)
                        is_visible = st.session_state[show_password_key]
                        password_to_display = data.get('password', 'ERRORE') if is_visible else "∗∗∗∗∗∗∗∗∗"
                        st.text_input("Password", value=password_to_display, disabled=True, key=f"disp_pwd_{service}")
                        c1, c2, c3 = st.columns(3)
                        button_label = "Nascondi Password" if is_visible else "Mostra Password"
                        if c1.button(button_label, key=f"toggle_{service}"):
                            st.session_state[show_password_key] = not st.session_state[show_password_key]
                            st.rerun()
                        if c2.button("Modifica", key=f"edit_{service}"):
                            st.session_state[show_password_key] = False
                            st.session_state.editing_service = service
                            st.rerun()
                        if c3.button("🗑️ Elimina", key=f"del_{service}", type="primary"):
                            manager.delete_credential(service)
                            st.success(f"Credenziale per '{service}' eliminata.")
                            st.rerun()

        elif scelta == "➕ Aggiungi Nuova":
            # ... (codice aggiungi invariato)
            st.header("Aggiungi Nuova Credenziale")
            with st.expander("✨ Generatore Password"):
                g1, g2 = st.columns(2)
                length = g1.slider("Lunghezza", 8, 128, 20)
                exclude_ambiguous = g2.checkbox("Escludi caratteri ambigui (Il1O0|')", True)
                g_opts = st.columns(4)
                use_upper = g_opts[0].checkbox("Maiuscole (A-Z)", True)
                use_lower = g_opts[1].checkbox("Minuscole (a-z)", True)
                use_digits = g_opts[2].checkbox("Numeri (0-9)", True)
                use_symbols = g_opts[3].checkbox("Simboli (@#$%)", True)
                if st.button("Genera e usa password"):
                    st.session_state.add_password_value = generate_random_password(length, use_upper, use_lower,
                                                                                   use_digits, use_symbols,
                                                                                   exclude_ambiguous)
            if 'add_password_value' in st.session_state: st.code(st.session_state.add_password_value)
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
                        st.error(f"Un servizio con nome '{service}' esiste già.")
                    else:
                        if manager.add_credential(service, username, password):
                            st.success(f"Credenziale per '{service}' aggiunta!")
                            if 'add_password_value' in st.session_state: del st.session_state.add_password_value
                            st.rerun()
                        else:
                            st.error("Errore durante il salvataggio.")

        # --- (Sezione Dashboard Sicurezza invariata) ---
        elif scelta == "🛡️ Dashboard Sicurezza":
            st.header("🛡️ Dashboard di Sicurezza")
            st.info("Questa sezione analizza le tue password per identificare potenziali rischi.")

            # 1. Analisi Password Riutilizzate
            with st.expander("🚨 Password Riutilizzate", expanded=True):
                password_map = {}
                for service, data in decrypted_passwords.items():
                    pwd = data.get('password')
                    if not pwd or "ERRORE" in pwd: continue
                    if pwd not in password_map:
                        password_map[pwd] = []
                    password_map[pwd].append(service)

                reused_passwords = {pwd: services for pwd, services in password_map.items() if len(services) > 1}

                if not reused_passwords:
                    st.success("Ottimo! Nessuna password riutilizzata trovata.")
                else:
                    st.error(
                        f"Trovate {len(reused_passwords)} password riutilizzate. È fondamentale usare una password unica per ogni servizio.")
                    for pwd, services in reused_passwords.items():
                        st.warning(f"La password usata per **{', '.join(services)}** è la stessa.")

            # 2. Analisi Password Deboli
            with st.expander("😟 Password Deboli", expanded=True):
                weak_passwords = []
                for service, data in decrypted_passwords.items():
                    pwd = data.get('password')
                    if not pwd or "ERRORE" in pwd: continue
                    strength = zxcvbn(pwd)
                    if strength['score'] < 3:  # Considera deboli le password con score 0, 1, 2
                        weak_passwords.append((service, strength['score']))

                if not weak_passwords:
                    st.success("Perfetto! Tutte le tue password sono robuste.")
                else:
                    st.error(f"Trovate {len(weak_passwords)} password deboli o molto deboli.")
                    for service, score in weak_passwords:
                        st.warning(f"La password per **{service}** ha un punteggio di robustezza basso ({score}/4).")

            # 3. Analisi Password Anziane
            with st.expander("🗓️ Password Anziane (più di 1 anno)", expanded=True):
                old_passwords = []
                one_year_ago = datetime.now() - timedelta(days=365)
                for service, data in decrypted_passwords.items():
                    last_updated_str = data.get('last_updated')
                    if last_updated_str:
                        last_updated_date = datetime.fromisoformat(last_updated_str)
                        if last_updated_date < one_year_ago:
                            old_passwords.append(service)

                if not old_passwords:
                    st.success("Tutte le tue password sono state aggiornate di recente.")
                else:
                    st.warning(
                        f"Trovate {len(old_passwords)} password non aggiornate da più di un anno. Considera di cambiarle.")
                    for service in old_passwords:
                        st.markdown(f"- **{service}**")

        # --- SEZIONE UTILITY (AGGIORNATA) ---
        elif scelta == "⚙️ Utility":
            st.header("Utility Database")

            # --- SEZIONE IMPORT/EXPORT (Invariata) ---
            st.subheader("📤 Esporta Database")
            st.warning("Assicurati che il file importato sia stato criptato con la stessa Master Password.")
            db_data = manager.load_encrypted_db()
            if not db_data:
                st.info("Nessun dato da esportare.")
            else:
                st.download_button("Scarica Backup Criptato (.json)", json.dumps(db_data, indent=4),
                                   "password_backup.json", "application/json")

            st.subheader("📥 Importa Database")
            uploaded_file = st.file_uploader("Carica un file di backup (.json)", type="json")
            if uploaded_file:
                try:
                    imported_data = json.load(uploaded_file)
                    st.success(f"File '{uploaded_file.name}' caricato con {len(imported_data)} voci.")
                    if st.button("Sostituisci Database con l'Importazione", type="primary"):
                        manager.save_encrypted_db(imported_data)
                        st.success("Database importato!")
                        st.rerun()
                except Exception as e:
                    st.error(f"Errore durante l'importazione: {e}")

            st.markdown("---")

            # --- NUOVA SEZIONE: CAMBIA MASTER PASSWORD ---
            st.subheader("🔑 Cambia Master Password")
            st.error("ATTENZIONE: Questa operazione è irreversibile. L'intero database verrà ri-criptato.")

            with st.form("change_master_pwd_form"):
                old_pwd = st.text_input("Vecchia Master Password", type="password",
                                        help="Inserisci la password che stai usando ora.")
                new_pwd = st.text_input("Nuova Master Password", type="password")
                confirm_pwd = st.text_input("Conferma Nuova Master Password", type="password")

                # Mostra la robustezza della *nuova* password
                display_strength_bar(new_pwd)

                submitted = st.form_submit_button("Cambia Master Password Ora", type="primary")

                if submitted:
                    # Validazioni UI
                    if not old_pwd or not new_pwd or not confirm_pwd:
                        st.error("Tutti i campi sono obbligatori.")
                    elif new_pwd != confirm_pwd:
                        st.error("Le nuove password non coincidono.")
                    elif old_pwd != st.session_state.master_password_cache:
                        st.error(
                            "La 'Vecchia Master Password' inserita non corrisponde a quella della sessione corrente.")
                    else:
                        # Controllo robustezza
                        _, _, score, _ = get_password_strength_feedback(new_pwd)
                        if score < 3:
                            st.warning("La nuova password è troppo debole. Scegli una combinazione più robusta.")
                        else:
                            # Esegui l'operazione
                            st.info("Sto cambiando la Master Password... Questo potrebbe richiedere un momento.")
                            success, message = manager.change_master_password(old_pwd, new_pwd)

                            if success:
                                st.success(message)
                                # Aggiorna la cache della sessione con la nuova password
                                st.session_state.master_password_cache = new_pwd
                                st.info("La sessione è stata aggiornata. Non è necessario un nuovo login.")
                                st.rerun()
                            else:
                                st.error(f"Errore: {message}")


if __name__ == "__main__":
    main()