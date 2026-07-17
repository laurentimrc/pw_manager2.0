import streamlit as st
import json
from datetime import datetime, timedelta

from password_manager import (
    PasswordManager,
    compute_security_flags,
    get_password_strength_feedback,
    generate_random_password,
    generate_totp_code,
    sort_credentials,
    validate_imported_db,
)

FLAG_LABELS = {"weak": "⚠️ Debole", "reused": "🔁 Riutilizzata", "old": "🗓️ Anziana"}

# --- CONFIGURAZIONE INIZIALE STREAMLIT ---
st.set_page_config(page_title="Password Manager Pro", page_icon="🔐", layout="wide",
                    initial_sidebar_state="expanded")

# --- COSTANTI DI CONFIGURAZIONE ---
PASSWORDS_FILE = "passwords.json"
MASTER_HASH_FILE = "master_pwd.hash"
KDF_SALT_FILE = "kdf.salt"
MAX_LOGIN_ATTEMPTS = 5
LOGIN_LOCKOUT_SECONDS = 60
SESSION_INACTIVITY_TIMEOUT_SECONDS = 15 * 60

CUSTOM_CSS = """
<style>
div[data-testid="stExpander"] {
    border-radius: 12px;
    border: 1px solid rgba(128, 128, 128, 0.18);
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05);
}
div[data-testid="stMetric"] {
    background: var(--secondary-background-color);
    border-radius: 10px;
    padding: 0.6rem 1rem;
    border: 1px solid rgba(128, 128, 128, 0.15);
}
.pwm-badge {
    display: inline-block;
    padding: 0.15rem 0.6rem;
    border-radius: 999px;
    background: rgba(255, 174, 0, 0.15);
    color: #b9770e;
    font-size: 0.78rem;
    font-weight: 600;
}
</style>
"""


def display_strength_bar(password: str):
    if not password:
        return
    strength_text, feedback, score, color = get_password_strength_feedback(password)
    st.progress((score + 1) / 5)
    feedback_suffix = f" · *{feedback}*" if feedback else ""
    st.markdown(
        f"**Robustezza:** <span style='color:{color}; font-weight:bold;'>{strength_text}</span>{feedback_suffix}",
        unsafe_allow_html=True)


# --- INTERFACCIA PRINCIPALE STREAMLIT ---
def main():
    st.markdown(CUSTOM_CSS, unsafe_allow_html=True)
    st.title("🔐 Password Manager Pro")
    st.markdown('<span class="pwm-badge">⚠️ Progetto a scopo didattico</span>', unsafe_allow_html=True)
    st.write("")

    manager = PasswordManager(MASTER_HASH_FILE, KDF_SALT_FILE, PASSWORDS_FILE)

    # --- (Logica di Setup e Login invariata) ---
    if "authenticated" not in st.session_state:
        st.session_state.authenticated = False
    if "editing_service" not in st.session_state:
        st.session_state.editing_service = None
    if "pending_delete" not in st.session_state:
        st.session_state.pending_delete = None

    if not manager.master_hash_exists():
        _, mid, _ = st.columns([1, 1.3, 1])
        with mid:
            with st.container(border=True):
                st.subheader("🔐 Imposta la tua Master Password")
                st.caption("Benvenuto! Crea una password principale robusta per proteggere il tuo database.")
                with st.form("setup_form"):
                    new_pwd = st.text_input("Nuova Master Password", type="password")
                    confirm_pwd = st.text_input("Conferma Master Password", type="password")
                    display_strength_bar(new_pwd)
                    submitted = st.form_submit_button("Imposta e Accedi", use_container_width=True,
                                                       type="primary")
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
        _, mid, _ = st.columns([1, 1.3, 1])
        with mid:
            with st.container(border=True):
                st.subheader("🔓 Login")

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
                        submitted = st.form_submit_button("Sblocca", use_container_width=True, type="primary")
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

        decrypted_passwords = manager.get_decrypted_passwords()
        if decrypted_passwords is None:
            st.error("Impossibile decriptare i dati.")
            st.stop()

        st.sidebar.markdown("### 🔐 Password Manager Pro")
        st.sidebar.success("✅ Accesso Eseguito")
        st.sidebar.caption(f"{len(decrypted_passwords)} credenziali salvate")
        if st.sidebar.button("🔒 Blocca App", use_container_width=True, type="primary"):
            for key in list(st.session_state.keys()): del st.session_state[key]
            st.rerun()

        st.sidebar.divider()
        menu_options = ["👀 Visualizza/Modifica", "➕ Aggiungi Nuova", "🛡️ Dashboard Sicurezza", "⚙️ Utility"]
        scelta = st.sidebar.radio("Menu", menu_options)

        if scelta == "👀 Visualizza/Modifica":
            st.header("Visualizza, Modifica ed Elimina Credenziali")
            search_col, sort_col = st.columns([2, 1])
            search_term = search_col.text_input("Cerca per Servizio", placeholder="Es. Google, Amazon...").lower()
            sort_label = sort_col.selectbox(
                "Ordina per", ["Nome (A-Z)", "Ultima modifica", "Robustezza (più deboli prima)"])
            sort_key = {"Nome (A-Z)": "name", "Ultima modifica": "recent",
                        "Robustezza (più deboli prima)": "weakest"}[sort_label]

            if search_term != st.session_state.get("prev_search_term", ""):
                st.session_state.pending_delete = None
            st.session_state.prev_search_term = search_term

            filtered_creds = {s: d for s, d in decrypted_passwords.items() if
                              search_term in s.lower()} if search_term else decrypted_passwords
            sorted_creds = sort_credentials(filtered_creds, sort_key)

            if filtered_creds:
                st.caption(f"{len(filtered_creds)} di {len(decrypted_passwords)} credenziali")
            else:
                st.info("Nessuna credenziale trovata.")

            security_flags = compute_security_flags(decrypted_passwords)

            for service, data in sorted_creds:
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
                    service_flags = security_flags.get(service, [])
                    label_suffix = f" — {' · '.join(FLAG_LABELS[f] for f in service_flags)}" if service_flags else ""

                    with st.expander(f"🔑 {service}{label_suffix}"):
                        st.caption("Username/Email")
                        st.code(data['username'], language=None)

                        is_visible = st.session_state[show_password_key]
                        st.caption("Password")
                        password_to_display = data.get('password', 'ERRORE') if is_visible else "••••••••••"
                        st.code(password_to_display, language=None)

                        # --- NUOVA SEZIONE TOTP ---
                        if data.get("totp_secret"):
                            st.markdown("---")
                            totp_container = st.container()
                            code, remaining = generate_totp_code(data['totp_secret'])

                            if code == "Errore":
                                totp_container.error("Formato segreto TOTP non valido.")
                            elif code:
                                totp_container.caption("Codice 2FA")
                                totp_container.code(code, language=None)
                                totp_container.progress(remaining / 30.0, text=f"Nuovo codice tra {remaining}s")
                                if totp_container.button("🔄 Aggiorna Codice", key=f"refresh_totp_{service}",
                                                         help="Forza l'aggiornamento del codice"):
                                    st.rerun()
                            else:
                                totp_container.info("Errore sconosciuto nella generazione TOTP.")
                        # --- FINE SEZIONE TOTP ---

                        st.markdown("---")  # Separatore visuale

                        if st.session_state.get("pending_delete") == service:
                            st.warning(f"Confermi l'eliminazione di **{service}**? L'azione è irreversibile.")
                            dc1, dc2 = st.columns(2)
                            if dc1.button("✅ Conferma eliminazione", key=f"confirm_del_{service}",
                                         type="primary", use_container_width=True):
                                manager.delete_credential(service)
                                st.session_state.pending_delete = None
                                st.success(f"Credenziale per '{service}' eliminata.")
                                st.rerun()
                            if dc2.button("Annulla", key=f"cancel_del_{service}", use_container_width=True):
                                st.session_state.pending_delete = None
                                st.rerun()
                        else:
                            c1, c2, c3 = st.columns(3)
                            button_label = "Nascondi Password" if is_visible else "Mostra Password"
                            if c1.button(button_label, key=f"toggle_{service}"):
                                st.session_state[show_password_key] = not st.session_state[show_password_key]
                                st.rerun()
                            if c2.button("Modifica", key=f"edit_{service}"):
                                st.session_state[show_password_key] = False  # Nascondi pwd prima di modificare
                                st.session_state.editing_service = service
                                st.rerun()
                            if c3.button("🗑️ Elimina", key=f"del_{service}"):
                                st.session_state.pending_delete = service
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
            if 'add_password_value' in st.session_state:
                st.code(st.session_state.add_password_value, language=None)
                display_strength_bar(st.session_state.add_password_value)

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
            st.header("🛡️ Dashboard di Sicurezza")
            st.info("Questa sezione analizza le tue password per identificare potenziali rischi.")

            security_flags = compute_security_flags(decrypted_passwords)

            password_map = {}
            weak_passwords = []
            old_passwords = []
            for service, data in decrypted_passwords.items():
                pwd = data.get('password')
                if pwd and "ERRORE" not in pwd:
                    password_map.setdefault(pwd, []).append(service)
                    if "weak" in security_flags.get(service, []):
                        _, _, score, _ = get_password_strength_feedback(pwd)
                        weak_passwords.append((service, score))
                if "old" in security_flags.get(service, []):
                    old_passwords.append(service)
            reused_passwords = {pwd: services for pwd, services in password_map.items() if len(services) > 1}

            m1, m2, m3, m4 = st.columns(4)
            m1.metric("Credenziali totali", len(decrypted_passwords))
            m2.metric("Password deboli", len(weak_passwords))
            m3.metric("Riutilizzate", len(reused_passwords))
            m4.metric("Anziane (>1 anno)", len(old_passwords))
            st.write("")

            with st.expander("🚨 Password Riutilizzate", expanded=True):
                if not reused_passwords:
                    st.success("Ottimo! Nessuna password riutilizzata trovata.")
                else:
                    st.error(
                        f"Trovate {len(reused_passwords)} password riutilizzate. È fondamentale usare una password unica per ogni servizio.")
                    for pwd, services in reused_passwords.items():
                        st.warning(f"La password usata per **{', '.join(services)}** è la stessa.")
            with st.expander("😟 Password Deboli", expanded=True):
                if not weak_passwords:
                    st.success("Perfetto! Tutte le tue password sono robuste.")
                else:
                    st.error(f"Trovate {len(weak_passwords)} password deboli o molto deboli.")
                    for service, score in weak_passwords:
                        st.warning(f"La password per **{service}** ha un punteggio di robustezza basso ({score}/4).")
            with st.expander("🗓️ Password Anziane (più di 1 anno)", expanded=True):
                if not old_passwords:
                    st.success("Tutte le tue password sono state aggiornate di recente.")
                else:
                    st.warning(
                        f"Trovate {len(old_passwords)} password non aggiornate da più di un anno. Considera di cambiarle.")
                    for service in old_passwords:
                        st.markdown(f"- **{service}**")

        elif scelta == "⚙️ Utility":
            st.header("Utility Database")
            tab_export, tab_import, tab_master = st.tabs(
                ["📤 Esporta", "📥 Importa", "🔑 Cambia Master Password"])

            with tab_export:
                st.subheader("📤 Esporta Database")
                st.caption("Il file scaricato contiene le tue credenziali ancora criptate.")
                db_data = manager.load_encrypted_db()
                if not db_data:
                    st.info("Nessun dato da esportare.")
                else:
                    st.download_button("Scarica Backup Criptato (.json)", json.dumps(db_data, indent=4),
                                       "password_backup.json", "application/json")

            with tab_import:
                st.subheader("📥 Importa Database")
                st.warning("Assicurati che il file importato sia stato criptato con la stessa Master Password.")
                uploaded_file = st.file_uploader("Carica un file di backup (.json)", type="json")
                if uploaded_file:
                    try:
                        imported_data = json.load(uploaded_file)
                        is_valid, validation_error = validate_imported_db(imported_data)
                        if not is_valid:
                            st.error(f"File di backup non valido: {validation_error}")
                        else:
                            st.success(f"File '{uploaded_file.name}' caricato con {len(imported_data)} voci.")
                            confirm_import = st.checkbox(
                                "Confermo di voler sostituire l'intero database attuale. L'operazione è irreversibile.")
                            if st.button("Sostituisci Database con l'Importazione", type="primary",
                                        disabled=not confirm_import):
                                manager.save_encrypted_db(imported_data)
                                st.success("Database importato!")
                                st.rerun()
                    except Exception as e:
                        st.error(f"Errore durante l'importazione: {e}")

            with tab_master:
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