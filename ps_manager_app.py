import streamlit as st
import json
from cryptography.fernet import Fernet
import base64
import random
import string
import bcrypt  # Per l'hashing della master password
import os
import hashlib  # Per PBKDF2HMAC (KDF)
from zxcvbn import zxcvbn  # Per la robustezza della password

# PRIMO COMANDO STREAMLIT DEVE ESSERE QUESTO:
st.set_page_config(page_title="Password Manager Pro", layout="wide")

# --- Costanti ---
PASSWORDS_FILE = "passwords.json"
MASTER_HASH_FILE = "master_pwd.hash"
KDF_SALT_FILE = "kdf.salt"
PBKDF2_ITERATIONS = 250000
AMBIGUOUS_CHARACTERS = "Il1O0|'`"


# --- Funzione Indicatore Robustezza Password ---
def get_password_strength_feedback(password):
    if not password:
        return "", "", 0, ""

    results = zxcvbn(password)
    score = results['score']
    feedback_text = results.get('feedback', {}).get('warning', '')
    suggestions = " ".join(results.get('feedback', {}).get('suggestions', []))

    full_feedback = feedback_text
    if suggestions:
        full_feedback += " " + suggestions if full_feedback else suggestions

    strength_map = {
        0: ("Pessima 😱", "red"), 1: ("Debole 😟", "orange"), 2: ("Discreta 🤔", "yellow"),
        3: ("Buona 😊", "lightgreen"), 4: ("Ottima! 💪", "green")
    }
    strength_text, color = strength_map.get(score, ("Sconosciuta", "grey"))

    return strength_text, full_feedback.strip(), score, color


# --- Funzione Generatore Password ---
def genera_password_casuale(length, use_uppercase, use_lowercase, use_digits, use_symbols, exclude_ambiguous):
    def filter_ambiguous(char_set_str):
        if exclude_ambiguous: return "".join(c for c in char_set_str if c not in AMBIGUOUS_CHARACTERS)
        return char_set_str

    s_upper, s_lower, s_digits, s_symbols = filter_ambiguous(string.ascii_uppercase), filter_ambiguous(
        string.ascii_lowercase), filter_ambiguous(string.digits), filter_ambiguous(string.punctuation)
    character_pool, guaranteed_chars = "", []

    if use_uppercase and s_upper: character_pool += s_upper; guaranteed_chars.append(random.choice(s_upper))
    if use_lowercase and s_lower: character_pool += s_lower; guaranteed_chars.append(random.choice(s_lower))
    if use_digits and s_digits: character_pool += s_digits; guaranteed_chars.append(random.choice(s_digits))
    if use_symbols and s_symbols: character_pool += s_symbols; guaranteed_chars.append(random.choice(s_symbols))

    if not character_pool: return "Errore: Seleziona tipi di caratteri validi."
    if length < len(guaranteed_chars): random.shuffle(guaranteed_chars); return "".join(guaranteed_chars[:length])

    remaining_length = length - len(guaranteed_chars)
    password_fill = [random.choice(character_pool) for _ in range(remaining_length)]
    final_password_list = guaranteed_chars + password_fill
    random.shuffle(final_password_list)
    return "".join(final_password_list)


# --- Gestione Master Password Hashing ---
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
    except ValueError:
        return False


# --- Gestione KDF e Chiave di Crittografia ---
def generate_and_save_kdf_salt():
    salt = os.urandom(16)
    with open(KDF_SALT_FILE, "wb") as f: f.write(salt)
    return salt


def load_kdf_salt():
    try:
        with open(KDF_SALT_FILE, "rb") as f:
            return f.read()
    except FileNotFoundError:
        return None


def derive_encryption_key(master_password_str, salt_bytes):
    if not master_password_str or not salt_bytes:
        raise ValueError("Master password e salt non possono essere vuoti.")
    password_bytes = master_password_str.encode('utf-8')
    derived_key_raw = hashlib.pbkdf2_hmac('sha256', password_bytes, salt_bytes, PBKDF2_ITERATIONS, dklen=32)
    return base64.urlsafe_b64encode(derived_key_raw)


def get_cipher_suite_kdf():
    if "derived_fernet_key" not in st.session_state or not st.session_state.derived_fernet_key:
        st.error("Chiave crittografia non disponibile. Eseguire login.")
        return None
    try:
        return Fernet(st.session_state.derived_fernet_key)
    except Exception as e:
        st.error(f"Errore init cipher suite: {e}"); return None


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
    if not cs: return None
    return cs.encrypt(messaggio_bytes)


def decripta_messaggio(messaggio_criptato_bytes):
    cs = get_cipher_suite_kdf()
    if not cs: return None
    try:
        return cs.decrypt(messaggio_criptato_bytes)
    except Exception:
        return None


# --- Interfaccia Streamlit ---
st.title("🔑 Password Manager Pro")
st.caption("⚠️ Esempio didattico. Valuta soluzioni professionali per dati critici.")

# Init session state keys
default_session_keys = {
    "authenticated": False, "derived_fernet_key": None,
    "master_password_strength_text": "", "master_password_strength_color": "grey",
    "master_password_feedback": "", "current_master_setup_pwd": "",
    "add_servizio_val": "", "add_username_val": "", "add_password_form_input_val": "",  # Valori per i campi di Add
    "generated_password_value_display_add": ""
}
for key, default_value in default_session_keys.items():
    if key not in st.session_state: st.session_state[key] = default_value

# Chiavi dei widget (non è necessario inizializzarle qui, Streamlit le crea)
# Solo per riferimento: "new_master_setup_widget_key", "confirm_master_setup_widget_key",
# "master_pwd_login_widget", "add_servizio_widget", "add_username_widget", "add_pwd_input_widget"

stored_master_hash = load_master_password_hash()
kdf_salt = load_kdf_salt()

if not stored_master_hash:
    st.subheader("🔑 Imposta la tua Master Password")
    st.info("Benvenuto! Configura la tua master password robusta.")

    new_master_pwd_val_typed = st.text_input(  # Leggiamo il valore direttamente dalla chiave del widget al submit
        "Nuova Master Password:", type="password", key="new_master_setup_widget_key",
        on_change=lambda: setattr(st.session_state, 'current_master_setup_pwd',
                                  st.session_state.new_master_setup_widget_key)
    )
    if st.session_state.current_master_setup_pwd:
        strength_text, feedback, _, color = get_password_strength_feedback(st.session_state.current_master_setup_pwd)
        st.markdown(f"Robustezza: <span style='color:{color}; font-weight:bold;'>{strength_text}</span>. {feedback}",
                    unsafe_allow_html=True)

    confirm_master_pwd_val_typed = st.text_input("Conferma Master Password:", type="password",
                                                 key="confirm_master_setup_widget_key")

    if st.button("Imposta e Accedi", key="setup_master_submit_btn"):
        current_pwd_to_set = st.session_state.current_master_setup_pwd  # Valore da on_change
        confirm_pwd_to_set = st.session_state.confirm_master_setup_widget_key  # Valore diretto dal widget

        if not current_pwd_to_set or not confirm_pwd_to_set:
            st.error("Entrambi i campi sono obbligatori.")
        elif len(current_pwd_to_set) < 12:
            st.error("Master password min 12 caratteri.")
        elif current_pwd_to_set != confirm_pwd_to_set:
            st.error("Le password non coincidono.")
        else:
            _, _, score, _ = get_password_strength_feedback(current_pwd_to_set)
            if score < 3:
                st.error("Master password troppo debole. Scegline una più robusta.")
            else:
                try:
                    set_master_password_hash(current_pwd_to_set)
                    current_kdf_salt = generate_and_save_kdf_salt()
                    fernet_key_for_session = derive_encryption_key(current_pwd_to_set, current_kdf_salt)
                    st.session_state.derived_fernet_key = fernet_key_for_session
                    st.session_state.authenticated = True
                    st.success("Master password impostata! Accesso effettuato.")
                    st.session_state.current_master_setup_pwd = ""  # Pulisci
                    # Non è necessario resettare le widget_key qui, verranno ricreate o il loro stato gestito da Streamlit
                    st.rerun()
                except Exception as e:
                    st.error(f"Errore: {e}")
    st.stop()

elif not st.session_state.authenticated:
    st.subheader("Login")
    master_password_input_login = st.text_input("Inserisci la Master Password:", type="password",
                                                key="master_pwd_login_widget")  # Chiave del widget
    if st.button("Sblocca", key="unlock_btn"):
        master_pwd_val_login = st.session_state.master_pwd_login_widget  # Leggi dalla chiave del widget
        if not kdf_salt:
            st.error("Errore critico: File KDF salt mancante. Resettare l'app.")
        elif verifica_master_password_con_hash(master_pwd_val_login, stored_master_hash):
            try:
                fernet_key_for_session = derive_encryption_key(master_pwd_val_login, kdf_salt)
                st.session_state.derived_fernet_key = fernet_key_for_session
                st.session_state.authenticated = True
                st.success("Accesso effettuato!")
                # st.session_state.master_pwd_login_widget = "" # Pulisce il campo al prossimo rerun se value non è bindato
                st.rerun()
            except ValueError as ve:
                st.error(f"Errore derivazione chiave: {ve}")
            except Exception as e:
                st.error(f"Errore login: {e}")
        else:
            st.error("Master Password errata.")
    st.stop()

# --- SEZIONE AUTENTICATA ---
st.sidebar.success("Accesso effettuato!")
if st.sidebar.button("Blocca App", key="lock_app_btn"):
    st.session_state.authenticated = False
    st.session_state.derived_fernet_key = None
    # Pulizia più selettiva o basata su prefissi per evitare di cancellare cose non volute
    keys_to_clear_on_logout = [
        "current_master_setup_pwd", "add_servizio_val", "add_username_val",
        "add_password_form_input_val", "generated_password_value_display_add",
        "master_pwd_login_widget"  # Per pulire il campo di login se l'utente fa logout e poi login
    ]
    for key_prefix_to_delete in ("edit_mode_", "show_pwd_", "edit_user_val_", "edit_pwd_val_"):
        for k in list(st.session_state.keys()):
            if k.startswith(key_prefix_to_delete):
                keys_to_clear_on_logout.append(k)

    for key in keys_to_clear_on_logout:
        if key in st.session_state:
            if isinstance(st.session_state[key], str):
                st.session_state[key] = ""
            elif isinstance(st.session_state[key], bool):
                st.session_state[key] = False
            # Aggiungi altri tipi se necessario, o semplicemente `del st.session_state[key]`
            # ma questo potrebbe dare errori se si tenta di accedere a una chiave cancellata
            # prima che sia reinizializzata. Impostare a default è più sicuro.
    st.rerun()

st.sidebar.markdown("---")
st.sidebar.header("Menu Principale")
menu_options = ["➕ Aggiungi Password", "👀 Visualizza/Modifica Password", "🗑️ Elimina Password", "⚙️ Utility Database"]
scelta = st.sidebar.radio("Naviga:", menu_options, key="main_menu_choice")

passwords_criptate_db = carica_passwords_criptate()

if scelta == "➕ Aggiungi Password":
    st.header("➕ Aggiungi Nuova Credenziale")
    st.markdown("#### ✨ Generatore Password Casuale")
    pwd_length_add = st.slider("Lunghezza:", 8, 64, 16, key="pwd_gen_length_add")
    cols_gen_add = st.columns(3)
    with cols_gen_add[0]:
        use_upper_add = st.checkbox("Maiuscole (A-Z)", True, key="pwd_gen_upper_add")
    with cols_gen_add[1]:
        use_digits_add = st.checkbox("Numeri (0-9)", True, key="pwd_gen_digits_add")
    with cols_gen_add[0]:
        use_lower_add = st.checkbox("Minuscole (a-z)", True, key="pwd_gen_lower_add")
    with cols_gen_add[1]:
        use_symbols_add = st.checkbox("Simboli (!@#$)", True, key="pwd_gen_symbols_add")
    with cols_gen_add[2]:
        exclude_ambiguous_add_val = st.checkbox("Escludi Ambigui", True, key="pwd_gen_exclude_ambiguous_add")

    if st.button("Genera Password", key="generate_pwd_btn_add"):
        if not (use_upper_add or use_lower_add or use_digits_add or use_symbols_add):
            st.error("Seleziona almeno un tipo di carattere.");
            st.session_state.generated_password_value_display_add = ""
        else:
            st.session_state.generated_password_value_display_add = genera_password_casuale(pwd_length_add,
                                                                                            use_upper_add,
                                                                                            use_lower_add,
                                                                                            use_digits_add,
                                                                                            use_symbols_add,
                                                                                            exclude_ambiguous_add_val)
            st.session_state.add_password_form_input_val = st.session_state.generated_password_value_display_add

    if st.session_state.generated_password_value_display_add:
        st.code(st.session_state.generated_password_value_display_add)
        s_text, s_feedback, _, s_color = get_password_strength_feedback(
            st.session_state.generated_password_value_display_add)
        st.markdown(
            f"Robustezza Generata: <span style='color:{s_color}; font-weight:bold;'>{s_text}</span>. {s_feedback}",
            unsafe_allow_html=True)
        st.caption("Password suggerita nel campo sottostante (puoi modificarla).")
    st.markdown("---")

    # --- Form Aggiungi (Senza st.form) ---
    # I valori sono bindati a st.session_state.add_XXX_val
    servizio_add_input = st.text_input("Servizio/Sito Web:", value=st.session_state.add_servizio_val,
                                       key="widget_add_servizio")
    username_add_input = st.text_input("Username/Email:", value=st.session_state.add_username_val,
                                       key="widget_add_username")


    def cb_update_add_pwd_strength():
        st.session_state.add_password_form_input_val = st.session_state.widget_add_password


    nuova_password_add_input = st.text_input("Password:", type="password", key="widget_add_password",
                                             value=st.session_state.add_password_form_input_val,
                                             on_change=cb_update_add_pwd_strength)

    if st.session_state.add_password_form_input_val:  # Mostra robustezza per il campo password
        s_text, s_feedback, _, s_color = get_password_strength_feedback(st.session_state.add_password_form_input_val)
        st.markdown(f"Robustezza: <span style='color:{s_color}; font-weight:bold;'>{s_text}</span>. {s_feedback}",
                    unsafe_allow_html=True)

    if st.button("Salva Credenziale", key="submit_add_credential_btn"):
        # Leggi i valori attuali dai widget usando le loro chiavi
        s_val = st.session_state.widget_add_servizio
        u_val = st.session_state.widget_add_username
        p_val = st.session_state.add_password_form_input_val  # Questo è aggiornato da on_change

        if s_val and u_val and p_val:
            enc_pass = cripta_messaggio(p_val.encode())
            if enc_pass:
                passwords_criptate_db[s_val] = {"username": u_val, "password_criptata": enc_pass.decode()}
                salva_passwords_criptate(passwords_criptate_db)
                st.success(f"Credenziale per '{s_val}' aggiunta!");
                # Pulisci le variabili di stato che controllano i valori dei widget
                st.session_state.add_servizio_val = ""
                st.session_state.add_username_val = ""
                st.session_state.add_password_form_input_val = ""
                st.session_state.generated_password_value_display_add = ""
                st.rerun()  # Rerun per riflettere i campi puliti
            else:
                st.error("Errore crittografia.")
        else:
            st.error("Compila tutti i campi.")

elif scelta == "👀 Visualizza/Modifica Password":
    st.header("👀 Visualizza e Modifica Credenziali")
    if not passwords_criptate_db:
        st.info("Nessuna password salvata.")
    else:
        search_term = st.text_input("Cerca per Servizio:", key="search_service_input_main").lower()
        filtered_credentials = {s: d for s, d in passwords_criptate_db.items() if
                                search_term in s.lower()} if search_term else passwords_criptate_db

        if not filtered_credentials and search_term: st.warning(f"Nessun servizio per '{search_term}'.")

        for servizio, dati in filtered_credentials.items():
            service_key_suffix = "".join(c if c.isalnum() else "_" for c in servizio)
            edit_mode_key = f"edit_mode_{service_key_suffix}"
            if edit_mode_key not in st.session_state: st.session_state[edit_mode_key] = False

            with st.expander(f"🔑 {servizio}", expanded=st.session_state[edit_mode_key]):
                if st.session_state[edit_mode_key]:
                    st.markdown(f"#### Modifica: {servizio}")

                    # Chiavi per i valori di session_state che mantengono lo stato del form di modifica
                    edit_user_sval_key = f"edit_user_val_{service_key_suffix}"
                    edit_pwd_sval_key = f"edit_pwd_val_{service_key_suffix}"
                    # Chiavi per i widget stessi
                    edit_user_widget_key = f"edit_user_widget_{service_key_suffix}"
                    edit_pwd_widget_key = f"edit_pwd_widget_{service_key_suffix}"

                    # Inizializza i valori di session_state se non esistono (prima volta in edit mode per questa entry)
                    if edit_user_sval_key not in st.session_state:
                        st.session_state[edit_user_sval_key] = dati['username']
                    if edit_pwd_sval_key not in st.session_state:
                        dec_pass_edit_init = decripta_messaggio(dati['password_criptata'].encode())
                        st.session_state[edit_pwd_sval_key] = dec_pass_edit_init.decode() if dec_pass_edit_init else ""


                    # Callback per aggiornare i valori di session_state quando i widget cambiano
                    def cb_edit_user():
                        st.session_state[edit_user_sval_key] = st.session_state[edit_user_widget_key]


                    def cb_edit_pwd():
                        st.session_state[edit_pwd_sval_key] = st.session_state[edit_pwd_widget_key]


                    new_username_edit_input = st.text_input("Username/Email:",
                                                            value=st.session_state[edit_user_sval_key],
                                                            key=edit_user_widget_key, on_change=cb_edit_user)
                    new_password_edit_input = st.text_input("Nuova Password:", type="password",
                                                            value=st.session_state[edit_pwd_sval_key],
                                                            key=edit_pwd_widget_key, on_change=cb_edit_pwd)

                    if st.session_state[edit_pwd_sval_key]:  # Mostra robustezza per la password in modifica
                        s_text, s_feedback, _, s_color = get_password_strength_feedback(
                            st.session_state[edit_pwd_sval_key])
                        st.markdown(
                            f"Robustezza: <span style='color:{s_color}; font-weight:bold;'>{s_text}</span>. {s_feedback}",
                            unsafe_allow_html=True)

                    cols_edit_btns = st.columns(2)
                    with cols_edit_btns[0]:
                        if st.button("Salva Modifiche", key=f"save_edit_{service_key_suffix}",
                                     use_container_width=True):
                            # Leggi i valori finali dalle variabili di session_state (aggiornate da on_change)
                            final_username = st.session_state[edit_user_sval_key]
                            final_pwd = st.session_state[edit_pwd_sval_key]

                            if not final_username:
                                st.error("L'username non può essere vuoto.")
                            else:
                                passwords_criptate_db[servizio]['username'] = final_username
                                dec_orig_pass_bytes = decripta_messaggio(dati['password_criptata'].encode())
                                original_password_str = dec_orig_pass_bytes.decode() if dec_orig_pass_bytes else ""

                                if final_pwd != original_password_str:  # Se la password è cambiata
                                    if not final_pwd:  # Se è stata cancellata, errore
                                        st.error(
                                            "Il campo password non può essere vuoto. Per non cambiarla, lasciala com'era.")
                                    else:  # Altrimenti, cripta e salva la nuova password
                                        enc_new_pass = cripta_messaggio(final_pwd.encode())
                                        if enc_new_pass:
                                            passwords_criptate_db[servizio]['password_criptata'] = enc_new_pass.decode()
                                        else:
                                            st.error("Errore crittografia nuova password. Modifiche NON salvate.");
                                            st.stop()

                                salva_passwords_criptate(passwords_criptate_db)
                                st.success(f"Credenziale per '{servizio}' aggiornata!")
                                st.session_state[edit_mode_key] = False
                                # Pulisci le session_state _val specifiche per questo form di modifica
                                del st.session_state[edit_user_sval_key]
                                del st.session_state[edit_pwd_sval_key]
                                st.rerun()
                    with cols_edit_btns[1]:
                        if st.button("Annulla", type="secondary", key=f"cancel_edit_{service_key_suffix}",
                                     use_container_width=True):
                            st.session_state[edit_mode_key] = False
                            # Pulisci le session_state _val specifiche per questo form di modifica
                            if edit_user_sval_key in st.session_state: del st.session_state[edit_user_sval_key]
                            if edit_pwd_sval_key in st.session_state: del st.session_state[edit_pwd_sval_key]
                            st.rerun()
                else:  # Modalità Visualizzazione
                    st.text(f"Username/Email: {dati['username']}")
                    show_pwd_key = f"show_pwd_{service_key_suffix}"
                    if show_pwd_key not in st.session_state: st.session_state[show_pwd_key] = False
                    if st.button("Mostra/Nascondi Password", key=f"btn_show_{service_key_suffix}"): st.session_state[
                        show_pwd_key] = not st.session_state[show_pwd_key]

                    if st.session_state[show_pwd_key]:
                        dec_pass_disp = decripta_messaggio(dati['password_criptata'].encode())
                        st.text_input("Password:", value=dec_pass_disp.decode() if dec_pass_disp else "ERRORE DECRIPT",
                                      type="default", disabled=True, key=f"pwd_vis_{service_key_suffix}")
                    else:
                        st.text_input("Password:", value="∗∗∗∗∗∗∗∗∗∗", type="default", disabled=True,
                                      key=f"pwd_hid_{service_key_suffix}")

                    if st.button("Modifica Credenziale", key=f"btn_edit_{service_key_suffix}", type="secondary"):
                        st.session_state[edit_mode_key] = True
                        # Pre-popola i valori di session_state per il form di modifica quando si clicca "Modifica"
                        st.session_state[f"edit_user_val_{service_key_suffix}"] = dati['username']
                        dec_pass_btn_edit = decripta_messaggio(dati['password_criptata'].encode())
                        st.session_state[
                            f"edit_pwd_val_{service_key_suffix}"] = dec_pass_btn_edit.decode() if dec_pass_btn_edit else ""
                        st.rerun()

elif scelta == "🗑️ Elimina Password":
    st.header("🗑️ Elimina Credenziale")
    if not passwords_criptate_db:
        st.info("Nessuna password da eliminare.")
    else:
        servizi_disponibili = list(passwords_criptate_db.keys())
        servizio_da_eliminare = st.selectbox("Seleziona il servizio da eliminare:", servizi_disponibili, index=None,
                                             placeholder="Scegli un servizio...")
        if servizio_da_eliminare:
            st.warning(
                f"Sei sicuro di voler eliminare la credenziale per **{servizio_da_eliminare}**? Questa azione è irreversibile.")
            if st.button(f"Sì, Elimina Definitivamente '{servizio_da_eliminare}'", type="primary"):
                if servizio_da_eliminare in passwords_criptate_db:
                    del passwords_criptate_db[servizio_da_eliminare]
                    salva_passwords_criptate(passwords_criptate_db)
                    st.success(f"Credenziale per '{servizio_da_eliminare}' eliminata!")
                    st.rerun()
                else:
                    st.error("Servizio non trovato.")

elif scelta == "⚙️ Utility Database":
    st.header("⚙️ Utility Database (Import/Export)")
    st.markdown("Esporta il tuo database di password criptate o importa un backup esistente.")
    st.markdown(
        "⚠️ **Attenzione:** L'import sovrascriverà le credenziali con lo stesso nome di servizio se scegli l'opzione 'Unisci e Sovrascrivi'. Assicurati che il file importato sia stato criptato con la stessa master password (o una derivata KDF compatibile) di quella attualmente in uso, altrimenti le password importate non saranno decriptabili.")

    st.subheader("📤 Esporta Database")
    if not passwords_criptate_db:
        st.info("Il database è vuoto. Nulla da esportare.")
    else:
        try:
            export_data_json = json.dumps(passwords_criptate_db, indent=4)
            st.download_button(label="Scarica Backup Password (passwords_backup.json)", data=export_data_json,
                               file_name="passwords_backup.json", mime="application/json")
        except Exception as e:
            st.error(f"Errore export: {e}")

    st.markdown("---");
    st.subheader("📥 Importa Database")
    uploaded_file = st.file_uploader("Scegli un file di backup (.json):", type="json", key="db_import_uploader")
    if uploaded_file is not None:
        try:
            imported_db = json.loads(uploaded_file.read().decode())
            if not isinstance(imported_db, dict):
                st.error("Formato file non valido.")
            else:
                valid_entries = all(
                    isinstance(v, dict) and "username" in v and "password_criptata" in v for v in imported_db.values())
                if not valid_entries and imported_db:
                    st.error("File JSON non sembra contenere credenziali valide.")
                else:
                    st.success(f"File '{uploaded_file.name}' caricato ({len(imported_db)} voci).")
                    import_option = st.radio("Modalità di import:",
                                             ("Unisci (sovrascrivi duplicati)", "Sostituisci database esistente"),
                                             key="import_mode_radio")
                    if st.button("Conferma Import", type="primary"):
                        current_db = carica_passwords_criptate()
                        final_db = imported_db if import_option == "Sostituisci database esistente" else {**current_db,
                                                                                                          **imported_db}
                        salva_passwords_criptate(final_db)
                        st.success(f"Database importato ('{import_option}').");
                        st.rerun()
        except json.JSONDecodeError:
            st.error("File non è JSON valido.")
        except Exception as e:
            st.error(f"Errore import: {e}")

st.sidebar.markdown("---")
st.sidebar.markdown(f"**Hash Master Pwd:** `{MASTER_HASH_FILE}`")
st.sidebar.markdown(f"**Salt KDF:** `{KDF_SALT_FILE}`")
st.sidebar.markdown(f"**Database Password:** `{PASSWORDS_FILE}`")