import base64
import hashlib
import json
import os
import random
import string
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

import bcrypt
import pyotp
from cryptography.fernet import Fernet
from zxcvbn import zxcvbn

PBKDF2_ITERATIONS = 600000
SYMBOLS = r"""!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~"""
AMBIGUOUS_CHARACTERS = "Il1O0|'`"


class PasswordManager:
    """
    Incapsula tutta la logica di gestione delle password.
    """

    def __init__(self, hash_file: str, salt_file: str, db_file: str):
        self.hash_file = hash_file
        self.salt_file = salt_file
        self.db_file = db_file
        self.cipher_suite: Optional[Fernet] = None

    # --- Master password ---
    def master_hash_exists(self) -> bool:
        return os.path.exists(self.hash_file)

    def load_master_hash(self) -> Optional[bytes]:
        if not self.master_hash_exists():
            return None
        with open(self.hash_file, "rb") as f:
            return f.read()

    def set_master_hash(self, password: str) -> None:
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
        with open(self.hash_file, "wb") as f:
            f.write(hashed_password)

    def verify_master_password(self, password: str) -> bool:
        stored_hash = self.load_master_hash()
        if not password or not stored_hash:
            return False
        try:
            return bcrypt.checkpw(password.encode('utf-8'), stored_hash)
        except ValueError:
            return False

    def load_kdf_salt(self) -> Optional[bytes]:
        if not os.path.exists(self.salt_file):
            return None
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
        if not self.cipher_suite:
            return None

        encrypted_db = self.load_encrypted_db()
        decrypted_data = {}
        for service, credentials in encrypted_db.items():
            try:
                decrypted_password = self.cipher_suite.decrypt(credentials['password_criptata'].encode()).decode()

                decrypted_totp = ""
                if credentials.get("totp_secret_criptato"):
                    decrypted_totp = self.cipher_suite.decrypt(credentials['totp_secret_criptato'].encode()).decode()

                decrypted_data[service] = {
                    "username": credentials['username'],
                    "password": decrypted_password,
                    "last_updated": credentials.get("last_updated"),
                    "totp_secret": decrypted_totp,
                }
            except Exception:
                decrypted_data[service] = {"password": "ERRORE DI DECRIPTAZIONE"}
        return decrypted_data

    def add_credential(self, service: str, username: str, password: str, totp_secret: str = "") -> bool:
        if not self.cipher_suite:
            return False

        encrypted_password = self.cipher_suite.encrypt(password.encode()).decode()

        encrypted_totp = ""
        if totp_secret:
            encrypted_totp = self.cipher_suite.encrypt(totp_secret.encode()).decode()

        db = self.load_encrypted_db()
        db[service] = {
            "username": username,
            "password_criptata": encrypted_password,
            "last_updated": datetime.now().isoformat(),
            "totp_secret_criptato": encrypted_totp,
        }
        self.save_encrypted_db(db)
        return True

    def update_credential(self, service: str, new_username: str, new_password: str,
                           new_totp_secret: str = "") -> bool:
        return self.add_credential(service, new_username, new_password, new_totp_secret)

    def delete_credential(self, service: str) -> None:
        db = self.load_encrypted_db()
        if service in db:
            del db[service]
            self.save_encrypted_db(db)

    def change_master_password(self, old_password: str, new_password: str) -> Tuple[bool, str]:
        if not self.verify_master_password(old_password):
            return False, "La vecchia Master Password è errata."

        old_salt = self.load_kdf_salt()
        if not old_salt:
            return False, "File salt KDF non trovato. Annullamento."

        old_key = hashlib.pbkdf2_hmac('sha256', old_password.encode('utf-8'), old_salt, PBKDF2_ITERATIONS, dklen=32)
        old_fernet_key = base64.urlsafe_b64encode(old_key)
        old_cipher = Fernet(old_fernet_key)

        encrypted_db = self.load_encrypted_db()
        decrypted_data_map = {}

        for service, credentials in encrypted_db.items():
            try:
                decrypted_password = old_cipher.decrypt(credentials['password_criptata'].encode()).decode()

                decrypted_totp = ""
                if credentials.get("totp_secret_criptato"):
                    decrypted_totp = old_cipher.decrypt(credentials['totp_secret_criptato'].encode()).decode()

                decrypted_data_map[service] = {
                    "username": credentials['username'],
                    "password": decrypted_password,
                    "totp_secret": decrypted_totp,
                    "last_updated": credentials.get("last_updated"),
                }
            except Exception:
                return False, f"Errore di decriptazione per '{service}'. Annullamento."

        self.set_master_hash(new_password)
        new_salt = self.generate_and_save_kdf_salt()
        new_key = hashlib.pbkdf2_hmac('sha256', new_password.encode('utf-8'), new_salt, PBKDF2_ITERATIONS, dklen=32)
        new_fernet_key = base64.urlsafe_b64encode(new_key)
        new_cipher = Fernet(new_fernet_key)

        new_encrypted_db = {}
        for service, data in decrypted_data_map.items():
            try:
                encrypted_password = new_cipher.encrypt(data['password'].encode()).decode()

                encrypted_totp = ""
                if data.get("totp_secret"):
                    encrypted_totp = new_cipher.encrypt(data['totp_secret'].encode()).decode()

                new_encrypted_db[service] = {
                    "username": data['username'],
                    "password_criptata": encrypted_password,
                    "totp_secret_criptato": encrypted_totp,
                    "last_updated": data.get("last_updated") or datetime.now().isoformat(),
                }
            except Exception as e:
                return False, f"Errore durante la ri-crittografia per '{service}': {e}"

        self.save_encrypted_db(new_encrypted_db)
        self.cipher_suite = new_cipher

        return True, "Master Password cambiata con successo!"


def get_password_strength_feedback(password: str) -> Tuple[str, str, int, str]:
    if not password:
        return "", "", 0, "grey"
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
    if not char_pool:
        return ""
    remaining_len = length - len(guaranteed_chars)
    if remaining_len < 0:
        random.shuffle(guaranteed_chars)
        return "".join(guaranteed_chars[:length])
    password_fill = random.choices(char_pool, k=remaining_len)
    final_password_list = guaranteed_chars + password_fill
    random.shuffle(final_password_list)
    return "".join(final_password_list)


def generate_totp_code(secret: str) -> Tuple[Optional[str], int]:
    """Genera il codice TOTP corrente e il tempo rimanente."""
    if not secret:
        return None, 0
    try:
        totp = pyotp.TOTP(secret)
        code = totp.now()
        remaining_time = totp.interval - (datetime.now().timestamp() % totp.interval)
        return code, int(remaining_time)
    except Exception:
        return "Errore", 0


def validate_imported_db(data: Any) -> Tuple[bool, str]:
    """Valida la struttura di un database importato prima di sovrascrivere quello esistente."""
    if not isinstance(data, dict):
        return False, "Il file importato deve contenere un oggetto JSON (servizio -> credenziali)."

    for service, credentials in data.items():
        if not isinstance(service, str) or not service:
            return False, "Trovato un nome di servizio non valido."
        if not isinstance(credentials, dict):
            return False, f"La voce '{service}' non è un oggetto valido."
        if "username" not in credentials or "password_criptata" not in credentials:
            return False, f"La voce '{service}' non contiene i campi obbligatori 'username' e 'password_criptata'."
        if not isinstance(credentials["username"], str) or not isinstance(credentials["password_criptata"], str):
            return False, f"La voce '{service}' ha campi 'username' o 'password_criptata' con tipo non valido."

        totp_secret_criptato = credentials.get("totp_secret_criptato", "")
        if totp_secret_criptato and not isinstance(totp_secret_criptato, str):
            return False, f"La voce '{service}' ha un campo 'totp_secret_criptato' con tipo non valido."

        last_updated = credentials.get("last_updated")
        if last_updated is not None:
            if not isinstance(last_updated, str):
                return False, f"La voce '{service}' ha un campo 'last_updated' con tipo non valido."
            try:
                datetime.fromisoformat(last_updated)
            except ValueError:
                return False, f"La voce '{service}' ha un campo 'last_updated' con formato data non valido."

    return True, ""


def compute_security_flags(decrypted_passwords: Dict[str, Dict[str, Any]]) -> Dict[str, List[str]]:
    """Calcola per ogni servizio gli indicatori di sicurezza: 'weak', 'reused', 'old'."""
    one_year_ago = datetime.now() - timedelta(days=365)

    password_owners: Dict[str, List[str]] = {}
    for service, data in decrypted_passwords.items():
        pwd = data.get("password")
        if pwd and "ERRORE" not in pwd:
            password_owners.setdefault(pwd, []).append(service)
    reused_services = {s for owners in password_owners.values() if len(owners) > 1 for s in owners}

    flags: Dict[str, List[str]] = {}
    for service, data in decrypted_passwords.items():
        service_flags = []

        pwd = data.get("password")
        if pwd and "ERRORE" not in pwd and zxcvbn(pwd)["score"] < 3:
            service_flags.append("weak")

        if service in reused_services:
            service_flags.append("reused")

        last_updated = data.get("last_updated")
        if last_updated:
            try:
                if datetime.fromisoformat(last_updated) < one_year_ago:
                    service_flags.append("old")
            except ValueError:
                pass

        flags[service] = service_flags

    return flags


def sort_credentials(decrypted_passwords: Dict[str, Dict[str, Any]],
                      sort_by: str = "name") -> List[Tuple[str, Dict[str, Any]]]:
    """Ordina le credenziali decriptate per nome, data di ultimo aggiornamento o robustezza."""
    items = list(decrypted_passwords.items())

    if sort_by == "recent":
        items.sort(key=lambda item: item[1].get("last_updated") or "", reverse=True)
    elif sort_by == "weakest":
        def score_of(item: Tuple[str, Dict[str, Any]]) -> int:
            pwd = item[1].get("password")
            if not pwd or "ERRORE" in pwd:
                return 5
            return zxcvbn(pwd)["score"]

        items.sort(key=score_of)
    else:
        items.sort(key=lambda item: item[0].lower())

    return items
