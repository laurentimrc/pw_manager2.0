"""Configurazione del backend FastAPI.

I percorsi dei file dati puntano di default alla radice del repository, in modo
che la webapp React operi sullo stesso "vault" (passwords.json, master_pwd.hash,
kdf.salt) usato dall'app Streamlit esistente: sono due interfacce per lo stesso
archivio locale, non due archivi separati.

Tutti i valori sono sovrascrivibili con variabili d'ambiente (usato soprattutto
nei test, che puntano a directory temporanee).
"""
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List

# app/config.py -> app -> backend -> webapp -> radice del repository
REPO_ROOT = Path(__file__).resolve().parents[3]


@dataclass
class Settings:
    hash_file: str
    salt_file: str
    db_file: str
    cookie_name: str = "pwm_session"
    cookie_secure: bool = False
    cors_origins: List[str] = field(default_factory=lambda: ["http://127.0.0.1:5173"])
    max_login_attempts: int = 5
    lockout_seconds: int = 60
    session_timeout_seconds: int = 15 * 60


def default_settings() -> Settings:
    """Costruisce la configurazione di default, leggendo eventuali override da env."""
    cors_env = os.environ.get("PWM_CORS_ORIGINS")
    cors_origins = [o.strip() for o in cors_env.split(",")] if cors_env else ["http://127.0.0.1:5173"]

    return Settings(
        hash_file=os.environ.get("PWM_HASH_FILE", str(REPO_ROOT / "master_pwd.hash")),
        salt_file=os.environ.get("PWM_SALT_FILE", str(REPO_ROOT / "kdf.salt")),
        db_file=os.environ.get("PWM_DB_FILE", str(REPO_ROOT / "passwords.json")),
        cookie_secure=os.environ.get("PWM_COOKIE_SECURE", "false").strip().lower() == "true",
        cors_origins=cors_origins,
        max_login_attempts=int(os.environ.get("PWM_MAX_LOGIN_ATTEMPTS", "5")),
        lockout_seconds=int(os.environ.get("PWM_LOCKOUT_SECONDS", "60")),
        session_timeout_seconds=int(os.environ.get("PWM_SESSION_TIMEOUT_SECONDS", str(15 * 60))),
    )
