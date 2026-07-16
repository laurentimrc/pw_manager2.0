import streamlit as st
import json
from datetime import datetime, timedelta

from password_manager import (
    PasswordManager,
    get_password_strength_feedback,
    generate_random_password,
    generate_totp_code,
    validate_imported_db,
)

# --- CONFIGURAZIONE INIZIALE STREAMLIT ---
st.set_page_config(page_title="Password Manager Pro", layout="wide", initial_sidebar_state="expanded")

# --- COSTANTI DI CONFIGURAZIONE ---
PASSWORDS_FILE = "passwords.json"
MASTER_HASH_FILE = "master_pwd.hash"
KDF_SALT_FILE = "kdf.salt"
MAX_LOGIN_ATTEMPTS = 5
LOGIN_LOCKOUT_SECONDS = 60
SESSION_INACTIVITY_TIMEOUT_SECONDS = 15 * 60


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
        st.subheader("Login")

        failed_attempts = st.session_state.get("failed_login_attempts", 0)
        lockout_until = st.session_state.get("login_lockout_until")
        now = datetime.now()

        if lockout_until and now < lockout_until:
            remaining = int((lockout_until - now).total_seconds())
            st.error(f"Troppi tentativi falliti. Riprova tra {remaining} secondi.")
        else:
            if lockout_until and now >= lockout_until:
                st.session_state.failed_login_attempts = 0
                st.session_state.login_lockout_until = None

            with st.form("login_form"):
                master_pwd_input = st.text_input("Inserisci la Master Password", type="password")
                submitted = st.form_submit_button("Sblocca")
                if submitted:
                    if manager.verify_master_password(master_pwd_input):
                        st.session_state.master_password_cache = master_pwd_input
                        st.session_state.authenticated = True
                        st.session_state.failed_login_attempts = 0
                        st.session_state.login_lockout_until = None
                        st.session_state.last_activity = datetime.now()
                        st.success("Accesso effettuato!")
                        st.rerun()
                    else:
                        st.session_state.failed_login_attempts = failed_attempts + 1
                        if st.session_state.failed_login_attempts >= MAX_LOGIN_ATTEMPTS:
                            st.session_state.login_lockout_until = datetime.now() + timedelta(
                                seconds=LOGIN_LOCKOUT_SECONDS)
                            st.error(
                                f"Troppi tentativi falliti. Account bloccato per {LOGIN_LOCKOUT_SECONDS} secondi.")
                        else:
                            remaining_attempts = MAX_LOGIN_ATTEMPTS - st.session_state.failed_login_attempts
                            st.error(f"Master Password errata. Tentativi rimasti: {remaining_attempts}.")
                        st.rerun()

    # --- APP PRINCIPALE ---
    else:
        kdf_salt = manager.load_kdf_salt()
        if not kdf_salt or 'master_password_cache' not in st.session_state:
            st.error("Errore di sessione. Eseguire nuovamente il login.")
            st.session_state.authenticated = False
            st.rerun()
            return

        last_activity = st.session_state.get("last_activity")
        if last_activity and (datetime.now() - last_activity).total_seconds() > SESSION_INACTIVITY_TIMEOUT_SECONDS:
            for key in list(st.session_state.keys()):
                del st.session_state[key]
            st.warning("Sessione scaduta per inattività. Effettua nuovamente il login.")
            st.rerun()
            return
        st.session_state.last_activity = datetime.now()

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

        if scelta == "👀 Visualizza/Modifica":
            st.header("Visualizza, Modifica ed Elimina Credenziali")
            search_term = st.text_input("Cerca per Servizio", placeholder="Es. Google, Amazon...").lower()
            filtered_creds = {s: d for s, d in decrypted_passwords.items() if
                              search_term in s.lower()} if search_term else decrypted_passwords
            if not filtered_creds: st.info("Nessuna credenziale trovata.")
            for service, data in filtered_creds.items():
                show_password_key = f"show_pwd_{service}"
                if show_password_key not in st.session_state: st.session_state[show_password_key] = False
                if st.session_state.editing_service == service:
                    # --- VISTA MODIFICA (AGGIORNATA) ---
                    with st.expander(f"📝 Modifica: **{service}**", expanded=True):
                        with st.form(key=f"edit_{service}"):
                            new_username = st.text_input("Username/Email", value=data['username'])
                            new_password = st.text_input("Password", value=data.get('password', ''), type="password")
                            display_strength_bar(new_password)
                            # NUOVO CAMPO TOTP
                            new_totp_secret = st.text_input("Segreto TOTP (opzionale)",
                                                            value=data.get('totp_secret', ''),
                                                            type="password",
                                                            help="Incolla la chiave segreta 2FA. Lascia vuoto per rimuovere.")

                            c1, c2 = st.columns(2)
                            if c1.form_submit_button("Salva Modifiche", use_container_width=True, type="primary"):
                                manager.update_credential(service, new_username, new_password,
                                                          new_totp_secret)  # Aggiornato
                                st.success(f"Credenziale per '{service}' aggiornata.")
                                st.session_state.editing_service = None
                                st.rerun()
                            if c2.form_submit_button("Annulla", use_container_width=True):
                                st.session_state.editing_service = None
                                st.rerun()
                else:
                    # --- VISTA VISUALIZZA (AGGIORNATA) ---
                    with st.expander(f"🔑 {service}"):
                        st.text_input("Username/Email", value=data['username'], disabled=True)
                        is_visible = st.session_state[show_password_key]
                        password_to_display = data.get('password', 'ERRORE') if is_visible else "∗∗∗∗∗∗∗∗∗"
                        st.text_input("Password", value=password_to_display, disabled=True, key=f"disp_pwd_{service}")

                        # --- NUOVA SEZIONE TOTP ---
                        if data.get("totp_secret"):
                            st.markdown("---")
                            totp_container = st.container()
                            code, remaining = generate_totp_code(data['totp_secret'])

                            if code == "Errore":
                                totp_container.error("Formato segreto TOTP non valido.")
                            elif code:
                                totp_container.metric(label="Codice 2FA", value=f"{code}")
                                totp_container.progress(remaining / 30.0, text=f"Nuovo codice tra {remaining}s")
                                if totp_container.button("🔄 Aggiorna Codice", key=f"refresh_totp_{service}",
                                                         help="Forza l'aggiornamento del codice"):
                                    st.rerun()
                            else:
                                totp_container.info("Errore sconosciuto nella generazione TOTP.")
                        # --- FINE SEZIONE TOTP ---

                        st.markdown("---")  # Separatore visuale
                        c1, c2, c3 = st.columns(3)
                        button_label = "Nascondi Password" if is_visible else "Mostra Password"
                        if c1.button(button_label, key=f"toggle_{service}"):
                            st.session_state[show_password_key] = not st.session_state[show_password_key]
                            st.rerun()
                        if c2.button("Modifica", key=f"edit_{service}"):
                            st.session_state[show_password_key] = False  # Nascondi pwd prima di modificare
                            st.session_state.editing_service = service
                            st.rerun()
                        if c3.button("🗑️ Elimina", key=f"del_{service}", type="primary"):
                            manager.delete_credential(service)
                            st.success(f"Credenziale per '{service}' eliminata.")
                            st.rerun()

        elif scelta == "➕ Aggiungi Nuova":
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

            # --- FORM AGGIUNGI (AGGIORNATO) ---
            with st.form("add_credential_form"):
                service = st.text_input("Servizio/Sito Web")
                username = st.text_input("Username/Email")
                password = st.text_input("Password", type="password",
                                         value=st.session_state.get("add_password_value", ""))
                display_strength_bar(password)

                # NUOVO CAMPO TOTP
                totp_secret = st.text_input("Segreto TOTP (opzionale)",
                                            type="password",
                                            help="Incolla qui la chiave segreta fornita dal servizio per il 2FA.")

                submitted = st.form_submit_button("Salva Credenziale", use_container_width=True, type="primary")
                if submitted:
                    if not all([service, username, password]):
                        st.error("I campi Servizio, Username e Password sono obbligatori.")
                    elif service in decrypted_passwords:
                        st.error(f"Un servizio con nome '{service}' esiste già.")
                    else:
                        if manager.add_credential(service, username, password, totp_secret):  # Aggiornato
                            st.success(f"Credenziale per '{service}' aggiunta!")
                            if 'add_password_value' in st.session_state: del st.session_state.add_password_value
                            st.rerun()
                        else:
                            st.error("Errore durante il salvataggio.")

        elif scelta == "🛡️ Dashboard Sicurezza":
            # ... (codice dashboard invariato) ...
            st.header("🛡️ Dashboard di Sicurezza")
            st.info("Questa sezione analizza le tue password per identificare potenziali rischi.")
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
            with st.expander("😟 Password Deboli", expanded=True):
                weak_passwords = []
                for service, data in decrypted_passwords.items():
                    pwd = data.get('password')
                    if not pwd or "ERRORE" in pwd: continue
                    _, _, score, _ = get_password_strength_feedback(pwd)
                    if score < 3:
                        weak_passwords.append((service, score))
                if not weak_passwords:
                    st.success("Perfetto! Tutte le tue password sono robuste.")
                else:
                    st.error(f"Trovate {len(weak_passwords)} password deboli o molto deboli.")
                    for service, score in weak_passwords:
                        st.warning(f"La password per **{service}** ha un punteggio di robustezza basso ({score}/4).")
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

        elif scelta == "⚙️ Utility":
            # ... (codice utility con cambio master password invariato) ...
            st.header("Utility Database")
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
                    is_valid, validation_error = validate_imported_db(imported_data)
                    if not is_valid:
                        st.error(f"File di backup non valido: {validation_error}")
                    else:
                        st.success(f"File '{uploaded_file.name}' caricato con {len(imported_data)} voci.")
                        if st.button("Sostituisci Database con l'Importazione", type="primary"):
                            manager.save_encrypted_db(imported_data)
                            st.success("Database importato!")
                            st.rerun()
                except Exception as e:
                    st.error(f"Errore durante l'importazione: {e}")
            st.markdown("---")
            st.subheader("🔑 Cambia Master Password")
            st.error("ATTENZIONE: Questa operazione è irreversibile. L'intero database verrà ri-criptato.")
            with st.form("change_master_pwd_form"):
                old_pwd = st.text_input("Vecchia Master Password", type="password",
                                        help="Inserisci la password che stai usando ora.")
                new_pwd = st.text_input("Nuova Master Password", type="password")
                confirm_pwd = st.text_input("Conferma Nuova Master Password", type="password")
                display_strength_bar(new_pwd)
                submitted = st.form_submit_button("Cambia Master Password Ora", type="primary")
                if submitted:
                    if not old_pwd or not new_pwd or not confirm_pwd:
                        st.error("Tutti i campi sono obbligatori.")
                    elif new_pwd != confirm_pwd:
                        st.error("Le nuove password non coincidono.")
                    elif old_pwd != st.session_state.master_password_cache:
                        st.error(
                            "La 'Vecchia Master Password' inserita non corrisponde a quella della sessione corrente.")
                    else:
                        _, _, score, _ = get_password_strength_feedback(new_pwd)
                        if score < 3:
                            st.warning("La nuova password è troppo debole. Scegli una combinazione più robusta.")
                        else:
                            st.info("Sto cambiando la Master Password... Questo potrebbe richiedere un momento.")
                            success, message = manager.change_master_password(old_pwd, new_pwd)
                            if success:
                                st.success(message)
                                st.session_state.master_password_cache = new_pwd
                                st.info("La sessione è stata aggiornata. Non è necessario un nuovo login.")
                                st.rerun()
                            else:
                                st.error(f"Errore: {message}")


if __name__ == "__main__":
    main()