"""Backend FastAPI di Password Manager Pro.

Riusa integralmente `password_manager.py` (radice del repository) per tutta la
logica di dominio: crittografia, TOTP, generazione password, validazione
import, calcolo dei flag di sicurezza, ordinamento. Questo modulo si limita a
esporre quella logica via HTTP e a gestire sessione/lockout/CORS.

Il server è pensato per ascoltare solo su 127.0.0.1 (vedi comando uvicorn nel
README): non implementa alcuna protezione per un'esposizione di rete più
ampia.
"""
import hmac
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

# Permette di importare `password_manager` dalla radice del repository senza
# duplicarne il codice. app/main.py -> app -> backend -> webapp -> radice.
_REPO_ROOT = Path(__file__).resolve().parents[3]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from password_manager import (  # noqa: E402  (import dopo la manipolazione di sys.path)
    ITEM_TYPE_CARD,
    ITEM_TYPE_LOGIN,
    ITEM_TYPE_NOTE,
    PasswordManager,
    VaultCorruptedError,
    check_password_breach,
    compute_security_flags,
    generate_random_password,
    generate_totp_code,
    get_password_strength_feedback,
    sort_credentials,
    validate_imported_db,
)

from .config import Settings, default_settings
from .schemas import (
    AddCardRequest,
    AddCredentialRequest,
    AddNoteRequest,
    ChangeMasterPasswordRequest,
    ImportRequest,
    LoginRequest,
    PasswordGeneratorRequest,
    PasswordStrengthRequest,
    RecoverCompleteRequest,
    RecoverVerifyRequest,
    RegenerateRecoveryCodeRequest,
    SetupRequest,
    UpdateCardRequest,
    UpdateCredentialRequest,
    UpdateNoteRequest,
)
from .sessions import LoginGuard, SessionData, SessionStore


def create_app(settings: Optional[Settings] = None) -> FastAPI:
    settings = settings or default_settings()

    app = FastAPI(title="Password Manager Pro API", version="1.0.0")
    app.state.settings = settings
    app.state.sessions = SessionStore()
    app.state.login_guard = LoginGuard(settings.max_login_attempts, settings.lockout_seconds)
    # Guard indipendente per il flusso di recovery: condiviso tra
    # /api/auth/recover/verify e /api/auth/recover perché entrambi tentano
    # di indovinare lo stesso segreto (il codice di recovery), quindi un
    # attaccante non deve poter aggirare il lockout distribuendo i tentativi
    # tra i due endpoint.
    app.state.recovery_guard = LoginGuard(settings.max_login_attempts, settings.lockout_seconds)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    sessions: SessionStore = app.state.sessions
    login_guard: LoginGuard = app.state.login_guard
    recovery_guard: LoginGuard = app.state.recovery_guard

    # --- Helpers interni ---
    def get_manager() -> PasswordManager:
        return PasswordManager(settings.hash_file, settings.salt_file, settings.db_file, settings.key_file)

    def manager_for_session(session: SessionData) -> PasswordManager:
        manager = get_manager()
        manager.cipher_suite = session.cipher
        return manager

    def is_session_expired(session: SessionData) -> bool:
        elapsed = (datetime.now() - session.last_activity).total_seconds()
        return elapsed > settings.session_timeout_seconds

    def set_session_cookie(response: Response, session_id: str) -> None:
        response.set_cookie(
            key=settings.cookie_name,
            value=session_id,
            httponly=True,
            secure=settings.cookie_secure,
            samesite="strict",
            path="/",
        )

    def clear_session_cookie(response: Response) -> None:
        response.delete_cookie(key=settings.cookie_name, path="/")

    def require_session(request: Request) -> SessionData:
        """Dependency per gli endpoint autenticati: valida la sessione e
        aggiorna il timestamp di ultima attività (equivalente del
        `last_activity` di Streamlit, aggiornato ad ogni interazione reale)."""
        session_id = request.cookies.get(settings.cookie_name)
        session = sessions.get(session_id)
        if not session:
            raise HTTPException(status_code=401, detail={"code": "not_authenticated",
                                                          "message": "Sessione non valida. Effettua il login."})
        if is_session_expired(session):
            sessions.destroy(session_id)
            raise HTTPException(status_code=401, detail={"code": "session_expired",
                                                          "message": "Sessione scaduta per inattività. "
                                                                     "Effettua nuovamente il login."})
        sessions.touch(session_id)
        return session

    # --- Auth ---
    @app.get("/api/auth/status")
    def auth_status(request: Request):
        manager = get_manager()
        setup_required = not manager.master_hash_exists()

        session_id = request.cookies.get(settings.cookie_name)
        session = sessions.get(session_id)
        authenticated = bool(session) and not is_session_expired(session)

        return {
            "setup_required": setup_required,
            "authenticated": authenticated,
            "lockout_remaining_seconds": login_guard.locked_remaining_seconds(),
            "session_timeout_seconds": settings.session_timeout_seconds,
        }

    @app.post("/api/auth/setup")
    def setup(payload: SetupRequest, response: Response):
        manager = get_manager()
        if manager.master_hash_exists():
            raise HTTPException(status_code=409, detail="La Master Password è già stata impostata.")
        if not payload.new_password or not payload.confirm_password:
            raise HTTPException(status_code=400, detail="Entrambi i campi sono obbligatori.")
        if len(payload.new_password) < 12:
            raise HTTPException(status_code=400, detail="La Master Password deve essere di almeno 12 caratteri.")
        if payload.new_password != payload.confirm_password:
            raise HTTPException(status_code=400, detail="Le password non coincidono.")
        _, _, score, _ = get_password_strength_feedback(payload.new_password)
        if score < 3:
            raise HTTPException(status_code=400, detail="Password debole. Scegli una combinazione più robusta.")

        manager.set_master_hash(payload.new_password)
        salt = manager.generate_and_save_kdf_salt()
        # Al primo sblocco di un vault appena creato, `derive_and_set_cipher`
        # minta la DEK e restituisce il primo codice di recovery: va mostrato
        # una sola volta all'utente subito dopo il setup (vedi frontend).
        try:
            recovery_code = manager.derive_and_set_cipher(payload.new_password, salt)
        except VaultCorruptedError:
            raise HTTPException(
                status_code=500,
                detail="Il materiale crittografico del vault risulta corrotto. Rimuovi vault_key.json "
                       "e riprova, oppure ripristina un backup.",
            )

        session_id = sessions.create(payload.new_password, manager.cipher_suite)
        login_guard.reset()
        set_session_cookie(response, session_id)
        return {"authenticated": True, "recovery_code": recovery_code}

    @app.post("/api/auth/login")
    def login(payload: LoginRequest, response: Response):
        manager = get_manager()
        if not manager.master_hash_exists():
            raise HTTPException(status_code=409, detail="Master Password non ancora impostata.")

        remaining_lockout = login_guard.locked_remaining_seconds()
        if remaining_lockout > 0:
            raise HTTPException(
                status_code=423,
                detail={"code": "locked_out",
                        "message": f"Troppi tentativi falliti. Riprova tra {remaining_lockout} secondi.",
                        "remaining_seconds": remaining_lockout},
            )

        if not manager.verify_master_password(payload.password):
            remaining_attempts = login_guard.register_failure()
            if remaining_attempts <= 0:
                raise HTTPException(
                    status_code=423,
                    detail={"code": "locked_out",
                            "message": f"Troppi tentativi falliti. Account bloccato per "
                                       f"{settings.lockout_seconds} secondi.",
                            "remaining_seconds": settings.lockout_seconds},
                )
            raise HTTPException(
                status_code=401,
                detail={"code": "wrong_password",
                        "message": f"Master Password errata. Tentativi rimasti: {remaining_attempts}.",
                        "remaining_attempts": remaining_attempts},
            )

        login_guard.reset()
        salt = manager.load_kdf_salt()
        if not salt:
            raise HTTPException(status_code=500, detail="File salt KDF non trovato.")
        # Non-None solo per un vault "legacy" (creato prima dell'introduzione
        # della DEK) che viene migrato automaticamente proprio in questo
        # login: in quel caso, come al setup, il nuovo codice di recovery va
        # mostrato una volta sola all'utente.
        try:
            recovery_code = manager.derive_and_set_cipher(payload.password, salt)
        except VaultCorruptedError:
            raise HTTPException(
                status_code=500,
                detail="Il materiale crittografico del vault risulta corrotto. Contatta l'amministratore "
                       "o ripristina un backup.",
            )

        session_id = sessions.create(payload.password, manager.cipher_suite)
        set_session_cookie(response, session_id)
        return {"authenticated": True, "recovery_code": recovery_code}

    @app.post("/api/auth/logout")
    def logout(request: Request, response: Response):
        session_id = request.cookies.get(settings.cookie_name)
        sessions.destroy(session_id)
        clear_session_cookie(response)
        return {"authenticated": False}

    # --- Recovery della Master Password dimenticata ---
    # Flusso in due chiamate, pensato per la UI "Hai dimenticato la Master
    # Password?": prima si verifica il codice da solo (per un errore chiaro
    # e immediato senza dover anche compilare la nuova password), poi si
    # invia codice + nuova Master Password insieme per completare il
    # recovery. Nessuna sessione viene creata qui: dopo il reset l'utente
    # effettua un login normale con la nuova Master Password, esattamente
    # come dopo un cambio Master Password "volontario".
    @app.post("/api/auth/recover/verify")
    def recover_verify(payload: RecoverVerifyRequest):
        manager = get_manager()
        if not manager.master_hash_exists():
            raise HTTPException(status_code=409, detail="Nessun vault esistente da recuperare.")

        remaining_lockout = recovery_guard.locked_remaining_seconds()
        if remaining_lockout > 0:
            raise HTTPException(
                status_code=423,
                detail={"code": "locked_out",
                        "message": f"Troppi tentativi falliti. Riprova tra {remaining_lockout} secondi.",
                        "remaining_seconds": remaining_lockout},
            )

        if not manager.verify_recovery_code(payload.recovery_code):
            remaining_attempts = recovery_guard.register_failure()
            if remaining_attempts <= 0:
                raise HTTPException(
                    status_code=423,
                    detail={"code": "locked_out",
                            "message": f"Troppi tentativi falliti. Riprova tra "
                                       f"{settings.lockout_seconds} secondi.",
                            "remaining_seconds": settings.lockout_seconds},
                )
            raise HTTPException(
                status_code=400,
                detail={"code": "invalid_recovery_code", "message": "Codice di recovery non valido."},
            )

        recovery_guard.reset()
        return {"valid": True}

    @app.post("/api/auth/recover")
    def recover_complete(payload: RecoverCompleteRequest):
        manager = get_manager()
        if not manager.master_hash_exists():
            raise HTTPException(status_code=409, detail="Nessun vault esistente da recuperare.")

        remaining_lockout = recovery_guard.locked_remaining_seconds()
        if remaining_lockout > 0:
            raise HTTPException(
                status_code=423,
                detail={"code": "locked_out",
                        "message": f"Troppi tentativi falliti. Riprova tra {remaining_lockout} secondi.",
                        "remaining_seconds": remaining_lockout},
            )

        if not payload.recovery_code or not payload.new_password or not payload.confirm_password:
            raise HTTPException(status_code=400, detail="Tutti i campi sono obbligatori.")
        if payload.new_password != payload.confirm_password:
            raise HTTPException(status_code=400, detail="Le nuove password non coincidono.")
        if len(payload.new_password) < 12:
            raise HTTPException(status_code=400, detail="La Master Password deve essere di almeno 12 caratteri.")
        _, _, score, _ = get_password_strength_feedback(payload.new_password)
        if score < 3:
            raise HTTPException(status_code=400,
                                detail="La nuova password è troppo debole. Scegli una combinazione più robusta.")

        dek = manager.recover_with_code(payload.recovery_code)
        if dek is None:
            remaining_attempts = recovery_guard.register_failure()
            if remaining_attempts <= 0:
                raise HTTPException(
                    status_code=423,
                    detail={"code": "locked_out",
                            "message": f"Troppi tentativi falliti. Riprova tra "
                                       f"{settings.lockout_seconds} secondi.",
                            "remaining_seconds": settings.lockout_seconds},
                )
            raise HTTPException(
                status_code=400,
                detail={"code": "invalid_recovery_code", "message": "Codice di recovery non valido."},
            )

        recovery_guard.reset()
        new_recovery_code = manager.complete_recovery(dek, payload.new_password)
        return {"recovery_code": new_recovery_code}

    # --- Password strength / generator (utilizzabili anche prima del login, es. setup) ---
    @app.post("/api/password-strength")
    def password_strength(payload: PasswordStrengthRequest):
        text, feedback, score, color = get_password_strength_feedback(payload.password)
        return {"text": text, "feedback": feedback, "score": score, "color": color}

    @app.post("/api/password-generator")
    def password_generator(payload: PasswordGeneratorRequest, _: SessionData = Depends(require_session)):
        password = generate_random_password(
            payload.length, payload.use_upper, payload.use_lower,
            payload.use_digits, payload.use_symbols, payload.exclude_ambiguous,
        )
        if not password:
            raise HTTPException(status_code=400, detail="Seleziona almeno un tipo di carattere.")
        return {"password": password}

    # --- Tag (trasversali a login/note/carte) ---
    def tags_by_key(manager: PasswordManager, item_type: Optional[str] = None) -> Dict[str, List[str]]:
        """Mappa chiave -> tag per tutte le voci del vault (o solo per un
        tipo), usando `get_decrypted_items` (mai `get_decrypted_passwords`,
        che non espone i tag - vedi password_manager.py)."""
        items = manager.get_decrypted_items() or []
        return {
            i["key"]: i.get("tags", [])
            for i in items
            if item_type is None or i.get("type", ITEM_TYPE_LOGIN) == item_type
        }

    @app.get("/api/tags")
    def list_tags(session: SessionData = Depends(require_session)):
        """Elenco di tutti i tag distinti usati nel vault (login + note +
        carte), usato dal frontend per costruire il filtro per tag."""
        manager = manager_for_session(session)
        all_tags = {tag for tags in tags_by_key(manager).values() for tag in tags}
        return {"tags": sorted(all_tags, key=str.lower)}

    # --- Credenziali ---
    @app.get("/api/credentials")
    def list_credentials(search: str = "", sort_by: str = "name", tag: str = "",
                          session: SessionData = Depends(require_session)):
        manager = manager_for_session(session)
        decrypted = manager.get_decrypted_passwords()
        if decrypted is None:
            raise HTTPException(status_code=500, detail="Impossibile decriptare i dati.")

        service_tags = tags_by_key(manager, ITEM_TYPE_LOGIN)
        flags = compute_security_flags(decrypted)
        search_lower = search.lower().strip()
        tag_filter = tag.strip()
        filtered = {
            s: d for s, d in decrypted.items()
            if (not search_lower or search_lower in s.lower())
            and (not tag_filter or tag_filter in service_tags.get(s, []))
        }
        ordered = sort_credentials(filtered, sort_by)

        items = []
        for service, data in ordered:
            items.append({
                "service": service,
                "username": data.get("username", ""),
                "last_updated": data.get("last_updated"),
                "has_totp": bool(data.get("totp_secret")),
                "flags": flags.get(service, []),
                "tags": service_tags.get(service, []),
                "decryption_error": "password" not in data or data.get("password") == "ERRORE DI DECRIPTAZIONE",
            })

        return {"items": items, "total": len(decrypted), "filtered_total": len(filtered)}

    @app.get("/api/credentials/{service}/secret")
    def get_credential_secret(service: str, session: SessionData = Depends(require_session)):
        manager = manager_for_session(session)
        decrypted = manager.get_decrypted_passwords() or {}
        if service not in decrypted:
            raise HTTPException(status_code=404, detail="Servizio non trovato.")
        data = decrypted[service]
        return {
            "service": service,
            "username": data.get("username", ""),
            "password": data.get("password", ""),
            "totp_secret": data.get("totp_secret", ""),
            "tags": tags_by_key(manager, ITEM_TYPE_LOGIN).get(service, []),
        }

    @app.get("/api/credentials/{service}/totp")
    def get_credential_totp(service: str, session: SessionData = Depends(require_session)):
        manager = manager_for_session(session)
        decrypted = manager.get_decrypted_passwords() or {}
        if service not in decrypted:
            raise HTTPException(status_code=404, detail="Servizio non trovato.")
        secret = decrypted[service].get("totp_secret")
        if not secret:
            raise HTTPException(status_code=400, detail="Nessun segreto TOTP configurato per questo servizio.")
        code, remaining = generate_totp_code(secret)
        if code == "Errore":
            raise HTTPException(status_code=400, detail="Formato segreto TOTP non valido.")
        return {"code": code, "remaining": remaining, "period": 30}

    @app.post("/api/credentials", status_code=201)
    def add_credential(payload: AddCredentialRequest, session: SessionData = Depends(require_session)):
        manager = manager_for_session(session)
        service = payload.service.strip()
        if not service or not payload.username or not payload.password:
            raise HTTPException(status_code=400,
                                detail="I campi Servizio, Username e Password sono obbligatori.")
        existing = manager.load_encrypted_db()
        if service in existing:
            raise HTTPException(status_code=409, detail=f"Un servizio con nome '{service}' esiste già.")
        manager.add_credential(service, payload.username, payload.password, payload.totp_secret, payload.tags)
        return {"service": service}

    @app.put("/api/credentials/{service}")
    def update_credential(service: str, payload: UpdateCredentialRequest,
                           session: SessionData = Depends(require_session)):
        manager = manager_for_session(session)
        existing = manager.load_encrypted_db()
        if service not in existing:
            raise HTTPException(status_code=404, detail="Servizio non trovato.")
        if not payload.username or not payload.password:
            raise HTTPException(status_code=400, detail="Username e Password sono obbligatori.")
        manager.update_credential(service, payload.username, payload.password, payload.totp_secret, payload.tags)
        return {"service": service}

    @app.delete("/api/credentials/{service}")
    def delete_credential(service: str, session: SessionData = Depends(require_session)):
        """Elimina una voce del vault per chiave: `PasswordManager.delete_credential`
        è generico rispetto al tipo (login, nota o carta), quindi questo stesso
        endpoint viene riusato dal frontend anche per eliminare note e carte,
        invece di duplicare la logica di cancellazione per ogni tipo."""
        manager = manager_for_session(session)
        existing = manager.load_encrypted_db()
        if service not in existing:
            raise HTTPException(status_code=404, detail="Voce non trovata.")
        manager.delete_credential(service)
        return {"deleted": service}

    # --- Note sicure ---
    @app.get("/api/notes")
    def list_notes(search: str = "", tag: str = "", session: SessionData = Depends(require_session)):
        manager = manager_for_session(session)
        items = manager.get_decrypted_items()
        if items is None:
            raise HTTPException(status_code=500, detail="Impossibile decriptare i dati.")
        notes = [i for i in items if i.get("type") == ITEM_TYPE_NOTE]

        search_lower = search.lower().strip()
        tag_filter = tag.strip()
        filtered = [
            n for n in notes
            if (not search_lower or search_lower in n["key"].lower())
            and (not tag_filter or tag_filter in n.get("tags", []))
        ]
        filtered.sort(key=lambda n: n["key"].lower())

        result_items = [{
            "key": n["key"],
            "tags": n.get("tags", []),
            "last_updated": n.get("last_updated"),
            "decryption_error": "error" in n,
        } for n in filtered]
        return {"items": result_items, "total": len(notes), "filtered_total": len(filtered)}

    @app.get("/api/notes/{key}/secret")
    def get_note_secret(key: str, session: SessionData = Depends(require_session)):
        manager = manager_for_session(session)
        items = manager.get_decrypted_items() or []
        note = next((i for i in items if i["key"] == key and i.get("type") == ITEM_TYPE_NOTE), None)
        if note is None:
            raise HTTPException(status_code=404, detail="Nota non trovata.")
        return {
            "key": key,
            "content": note.get("content", ""),
            "tags": note.get("tags", []),
            "last_updated": note.get("last_updated"),
        }

    @app.post("/api/notes", status_code=201)
    def add_note(payload: AddNoteRequest, session: SessionData = Depends(require_session)):
        manager = manager_for_session(session)
        title = payload.title.strip()
        if not title or not payload.content:
            raise HTTPException(status_code=400, detail="I campi Titolo e Contenuto sono obbligatori.")
        existing = manager.load_encrypted_db()
        if title in existing:
            raise HTTPException(status_code=409, detail=f"Una voce con nome '{title}' esiste già.")
        manager.add_note(title, payload.content, payload.tags)
        return {"key": title}

    @app.put("/api/notes/{key}")
    def update_note(key: str, payload: UpdateNoteRequest, session: SessionData = Depends(require_session)):
        manager = manager_for_session(session)
        existing = manager.load_encrypted_db()
        if key not in existing or existing[key].get("type") != ITEM_TYPE_NOTE:
            raise HTTPException(status_code=404, detail="Nota non trovata.")
        if not payload.content:
            raise HTTPException(status_code=400, detail="Il contenuto è obbligatorio.")
        manager.update_note(key, payload.content, payload.tags)
        return {"key": key}

    # --- Carte di pagamento ---
    @app.get("/api/cards")
    def list_cards(search: str = "", tag: str = "", session: SessionData = Depends(require_session)):
        manager = manager_for_session(session)
        items = manager.get_decrypted_items()
        if items is None:
            raise HTTPException(status_code=500, detail="Impossibile decriptare i dati.")
        cards = [i for i in items if i.get("type") == ITEM_TYPE_CARD]

        search_lower = search.lower().strip()
        tag_filter = tag.strip()
        filtered = [
            c for c in cards
            if (not search_lower or search_lower in c["key"].lower())
            and (not tag_filter or tag_filter in c.get("tags", []))
        ]
        filtered.sort(key=lambda c: c["key"].lower())

        result_items = []
        for c in filtered:
            number = c.get("card_number", "")
            last4 = number[-4:] if len(number) >= 4 else number
            result_items.append({
                "key": c["key"],
                # L'intestatario e la scadenza non sono considerati campi da
                # mascherare (solo numero carta e CVV lo sono, come richiesto):
                # possono comparire già nell'elenco, come lo username per i
                # login. Il numero completo e il CVV restano nascosti finché
                # non viene richiesto esplicitamente `/api/cards/{key}/secret`.
                "cardholder": c.get("cardholder", ""),
                "expiry": c.get("expiry", ""),
                "card_number_last4": last4,
                "tags": c.get("tags", []),
                "last_updated": c.get("last_updated"),
                "decryption_error": "error" in c,
            })
        return {"items": result_items, "total": len(cards), "filtered_total": len(filtered)}

    @app.get("/api/cards/{key}/secret")
    def get_card_secret(key: str, session: SessionData = Depends(require_session)):
        manager = manager_for_session(session)
        items = manager.get_decrypted_items() or []
        card = next((i for i in items if i["key"] == key and i.get("type") == ITEM_TYPE_CARD), None)
        if card is None:
            raise HTTPException(status_code=404, detail="Carta non trovata.")
        return {
            "key": key,
            "cardholder": card.get("cardholder", ""),
            "card_number": card.get("card_number", ""),
            "expiry": card.get("expiry", ""),
            "cvv": card.get("cvv", ""),
            "tags": card.get("tags", []),
            "last_updated": card.get("last_updated"),
        }

    @app.post("/api/cards", status_code=201)
    def add_card(payload: AddCardRequest, session: SessionData = Depends(require_session)):
        manager = manager_for_session(session)
        name = payload.name.strip()
        if not name or not payload.card_number:
            raise HTTPException(status_code=400, detail="I campi Nome e Numero Carta sono obbligatori.")
        existing = manager.load_encrypted_db()
        if name in existing:
            raise HTTPException(status_code=409, detail=f"Una voce con nome '{name}' esiste già.")
        manager.add_card(name, payload.cardholder, payload.card_number, payload.expiry, payload.cvv, payload.tags)
        return {"key": name}

    @app.put("/api/cards/{key}")
    def update_card(key: str, payload: UpdateCardRequest, session: SessionData = Depends(require_session)):
        manager = manager_for_session(session)
        existing = manager.load_encrypted_db()
        if key not in existing or existing[key].get("type") != ITEM_TYPE_CARD:
            raise HTTPException(status_code=404, detail="Carta non trovata.")
        if not payload.card_number:
            raise HTTPException(status_code=400, detail="Il numero carta è obbligatorio.")
        manager.update_card(key, payload.cardholder, payload.card_number, payload.expiry, payload.cvv, payload.tags)
        return {"key": key}

    # --- Dashboard sicurezza ---
    @app.get("/api/security/dashboard")
    def security_dashboard(session: SessionData = Depends(require_session)):
        manager = manager_for_session(session)
        decrypted = manager.get_decrypted_passwords() or {}
        flags = compute_security_flags(decrypted)

        password_map = {}
        weak_passwords = []
        old_passwords = []
        for service, data in decrypted.items():
            pwd = data.get("password")
            if pwd and "ERRORE" not in pwd:
                password_map.setdefault(pwd, []).append(service)
                if "weak" in flags.get(service, []):
                    _, _, score, _ = get_password_strength_feedback(pwd)
                    weak_passwords.append({"service": service, "score": score})
            if "old" in flags.get(service, []):
                old_passwords.append(service)
        reused_passwords = [{"services": services} for services in password_map.values() if len(services) > 1]

        return {
            "total_credentials": len(decrypted),
            "weak_count": len(weak_passwords),
            "reused_count": len(reused_passwords),
            "old_count": len(old_passwords),
            "weak_passwords": weak_passwords,
            "reused_passwords": reused_passwords,
            "old_passwords": old_passwords,
        }

    # --- Controllo violazioni note (HIBP Pwned Passwords, k-anonymity) ---
    # Va invocato solo su azione esplicita dell'utente (un bottone in
    # Dashboard Sicurezza), mai in automatico al caricamento della pagina:
    # è un controllo verso un'API pubblica di terzi, con un round-trip di
    # rete per ogni password (o gruppo di password uguali) da controllare.
    # `check_password_breach` invia in rete solo un prefisso a 5 caratteri
    # dell'hash SHA-1: né la password né l'hash completo lasciano mai questo
    # processo (vedi password_manager.py). Questi endpoint, a loro volta,
    # non restituiscono mai la password al frontend: solo il conteggio delle
    # violazioni (o l'indicazione che il controllo non è riuscito).
    @app.post("/api/credentials/{service}/breach-check")
    def check_credential_breach(service: str, session: SessionData = Depends(require_session)):
        manager = manager_for_session(session)
        decrypted = manager.get_decrypted_passwords() or {}
        if service not in decrypted:
            raise HTTPException(status_code=404, detail="Servizio non trovato.")
        password = decrypted[service].get("password")
        if not password or "ERRORE" in password:
            raise HTTPException(status_code=400, detail="Impossibile decriptare la password per questo servizio.")
        breach_count = check_password_breach(password)
        return {"service": service, "breach_count": breach_count, "checked": breach_count is not None}

    @app.post("/api/security/breach-check")
    def check_all_credentials_breach(session: SessionData = Depends(require_session)):
        """Controlla tutte le credenziali in un'unica azione esplicita.
        Deduplica per password: se più servizi condividono la stessa
        password (già segnalato come 'reused' in dashboard), viene fatta una
        sola chiamata HIBP per quel gruppo. Il fallimento del controllo su
        una password (rete assente, timeout) non blocca il controllo delle
        altre: viene semplicemente segnalato come 'checked: false' per i
        servizi coinvolti, mentre gli altri procedono normalmente."""
        manager = manager_for_session(session)
        decrypted = manager.get_decrypted_passwords() or {}

        password_to_services: Dict[str, List[str]] = {}
        for service, data in decrypted.items():
            pwd = data.get("password")
            if pwd and "ERRORE" not in pwd:
                password_to_services.setdefault(pwd, []).append(service)

        results = []
        for pwd, services in password_to_services.items():
            breach_count = check_password_breach(pwd)
            checked = breach_count is not None
            for service in services:
                results.append({"service": service, "breach_count": breach_count, "checked": checked})

        checked_services = {r["service"] for r in results}
        for service in decrypted:
            if service not in checked_services:
                # Credenziale non decriptabile ("ERRORE DI DECRIPTAZIONE"): non
                # esiste una password valida da controllare.
                results.append({"service": service, "breach_count": None, "checked": False})

        results.sort(key=lambda r: r["service"].lower())
        return {"results": results}

    # --- Utility: export / import / cambio master password ---
    @app.get("/api/utility/export")
    def export_db(session: SessionData = Depends(require_session)):
        manager = manager_for_session(session)
        data = manager.load_encrypted_db()
        return JSONResponse(
            content=data,
            headers={"Content-Disposition": 'attachment; filename="password_backup.json"'},
        )

    @app.post("/api/utility/import")
    def import_db(payload: ImportRequest, session: SessionData = Depends(require_session)):
        is_valid, error = validate_imported_db(payload.data)
        if not is_valid:
            raise HTTPException(
                status_code=400,
                detail={"code": "invalid_backup", "message": f"File di backup non valido: {error}"},
            )
        if not payload.confirm:
            # Dati validi ma conferma esplicita non ancora fornita: il frontend usa questo
            # ramo per mostrare all'utente il numero di voci prima di sostituire il database.
            raise HTTPException(
                status_code=400,
                detail={
                    "code": "confirmation_required",
                    "message": "Conferma esplicita richiesta per sostituire il database attuale.",
                    "entries": len(payload.data),
                },
            )
        manager = manager_for_session(session)
        manager.save_encrypted_db(payload.data)
        return {"imported_entries": len(payload.data)}

    @app.post("/api/utility/change-master-password")
    def change_master_password(payload: ChangeMasterPasswordRequest, request: Request,
                                session: SessionData = Depends(require_session)):
        if not payload.old_password or not payload.new_password or not payload.confirm_password:
            raise HTTPException(status_code=400, detail="Tutti i campi sono obbligatori.")
        if payload.new_password != payload.confirm_password:
            raise HTTPException(status_code=400, detail="Le nuove password non coincidono.")
        if not hmac.compare_digest(payload.old_password, session.master_password):
            raise HTTPException(
                status_code=400,
                detail="La 'Vecchia Master Password' inserita non corrisponde a quella della sessione corrente.",
            )
        _, _, score, _ = get_password_strength_feedback(payload.new_password)
        if score < 3:
            raise HTTPException(status_code=400,
                                detail="La nuova password è troppo debole. Scegli una combinazione più robusta.")

        manager = manager_for_session(session)
        success, message = manager.change_master_password(payload.old_password, payload.new_password)
        if not success:
            raise HTTPException(status_code=400, detail=message)

        session_id = request.cookies.get(settings.cookie_name)
        sessions.update_credentials(session_id, payload.new_password, manager.cipher_suite)
        return {"message": message}

    @app.post("/api/utility/recovery-code")
    def regenerate_recovery_code(payload: RegenerateRecoveryCodeRequest,
                                  session: SessionData = Depends(require_session)):
        """Genera un nuovo codice di recovery in qualunque momento da
        autenticati, senza cambiare la master password: invalida quello
        precedente. Richiede la master password corrente come conferma
        esplicita, stesso principio di change-master-password."""
        if not payload.current_password:
            raise HTTPException(status_code=400, detail="La Master Password corrente è obbligatoria.")
        if not hmac.compare_digest(payload.current_password, session.master_password):
            raise HTTPException(
                status_code=400,
                detail="La Master Password inserita non corrisponde a quella della sessione corrente.",
            )

        manager = get_manager()
        new_code = manager.regenerate_recovery_code(payload.current_password)
        if new_code is None:
            raise HTTPException(status_code=400, detail="Impossibile generare un nuovo codice di recovery.")
        return {"recovery_code": new_code}

    return app


app = create_app()
