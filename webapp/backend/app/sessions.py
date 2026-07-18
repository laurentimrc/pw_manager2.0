"""Session store e login guard, in-memory, lato server.

Il modello di sessione dell'app Streamlit teneva la master password nel
`st.session_state` del processo server per tutta la durata della sessione (per
poter ri-derivare il cipher Fernet ad ogni interazione). Qui replichiamo lo
stesso principio: la master password (e il cipher Fernet già derivato, per
evitare di ricalcolare PBKDF2-HMAC-SHA256 con 600.000 iterazioni ad ogni
richiesta) vivono SOLO in memoria di processo, indicizzati da un session id
opaco e casuale che il browser riceve in un cookie httpOnly. Il browser non
vede mai la master password né la chiave derivata.

Non c'è persistenza su disco delle sessioni: un riavvio del backend invalida
tutte le sessioni attive, esattamente come un riavvio del processo Streamlit
invalida `st.session_state`.
"""
import secrets
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, Optional

from cryptography.fernet import Fernet


@dataclass
class SessionData:
    master_password: str
    cipher: Fernet
    created_at: datetime
    last_activity: datetime


class SessionStore:
    """Store in-memoria delle sessioni autenticate, protetto da lock."""

    def __init__(self) -> None:
        self._sessions: Dict[str, SessionData] = {}
        self._lock = threading.Lock()

    def create(self, master_password: str, cipher: Fernet) -> str:
        session_id = secrets.token_urlsafe(32)
        now = datetime.now()
        with self._lock:
            self._sessions[session_id] = SessionData(
                master_password=master_password, cipher=cipher, created_at=now, last_activity=now
            )
        return session_id

    def get(self, session_id: Optional[str]) -> Optional[SessionData]:
        if not session_id:
            return None
        with self._lock:
            return self._sessions.get(session_id)

    def touch(self, session_id: str) -> None:
        with self._lock:
            session = self._sessions.get(session_id)
            if session:
                session.last_activity = datetime.now()

    def update_credentials(self, session_id: str, master_password: str, cipher: Fernet) -> None:
        with self._lock:
            session = self._sessions.get(session_id)
            if session:
                session.master_password = master_password
                session.cipher = cipher

    def destroy(self, session_id: Optional[str]) -> None:
        if not session_id:
            return
        with self._lock:
            self._sessions.pop(session_id, None)


class LoginGuard:
    """Traccia i tentativi di login falliti a livello di applicazione.

    L'app è single-user e ad uso locale (come l'originale Streamlit), quindi il
    contatore dei tentativi falliti e il cooldown sono globali al processo e
    non per-sessione: non esiste una sessione autenticata finché il login non
    riesce.
    """

    def __init__(self, max_attempts: int, lockout_seconds: int) -> None:
        self.max_attempts = max_attempts
        self.lockout_seconds = lockout_seconds
        self._failed_attempts = 0
        self._lockout_until: Optional[datetime] = None
        self._lock = threading.Lock()

    def locked_remaining_seconds(self) -> int:
        with self._lock:
            return self._remaining_locked_no_lock()

    def _remaining_locked_no_lock(self) -> int:
        now = datetime.now()
        if self._lockout_until and now < self._lockout_until:
            return int((self._lockout_until - now).total_seconds())
        if self._lockout_until and now >= self._lockout_until:
            self._failed_attempts = 0
            self._lockout_until = None
        return 0

    def register_failure(self) -> int:
        """Registra un tentativo fallito. Restituisce i tentativi rimasti (0 se ora bloccato)."""
        with self._lock:
            self._failed_attempts += 1
            if self._failed_attempts >= self.max_attempts:
                self._lockout_until = datetime.now() + timedelta(seconds=self.lockout_seconds)
                return 0
            return self.max_attempts - self._failed_attempts

    def reset(self) -> None:
        with self._lock:
            self._failed_attempts = 0
            self._lockout_until = None
