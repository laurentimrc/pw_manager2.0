"""Modelli Pydantic per le richieste/risposte dell'API.

Nota di sicurezza: nessuno di questi campi viene mai loggato esplicitamente
dal codice applicativo; FastAPI/uvicorn non loggano il body delle richieste
per default (solo metodo + path nell'access log).
"""
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class SetupRequest(BaseModel):
    new_password: str
    confirm_password: str


class LoginRequest(BaseModel):
    password: str


class RecoverVerifyRequest(BaseModel):
    recovery_code: str


class RecoverCompleteRequest(BaseModel):
    recovery_code: str
    new_password: str
    confirm_password: str


class AddCredentialRequest(BaseModel):
    service: str
    username: str
    password: str
    totp_secret: str = ""


class UpdateCredentialRequest(BaseModel):
    username: str
    password: str
    totp_secret: str = ""


class ImportRequest(BaseModel):
    data: Dict[str, Any]
    confirm: bool = False


class ChangeMasterPasswordRequest(BaseModel):
    old_password: str
    new_password: str
    confirm_password: str


class PasswordStrengthRequest(BaseModel):
    password: str = ""


class PasswordGeneratorRequest(BaseModel):
    length: int = Field(default=20, ge=1, le=256)
    use_upper: bool = True
    use_lower: bool = True
    use_digits: bool = True
    use_symbols: bool = True
    exclude_ambiguous: bool = True
