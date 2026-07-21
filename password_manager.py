import base64
import hashlib
import json
import os
import random
import secrets
import string
import urllib.error
import urllib.request
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

import bcrypt
import pyotp
from cryptography.fernet import Fernet
from zxcvbn import zxcvbn

PBKDF2_ITERATIONS = 600000
SYMBOLS = r"""!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~"""
AMBIGUOUS_CHARACTERS = "Il1O0|'`"

# Tipi di voce del vault. "login" è il default implicito per le voci
# esistenti create prima dell'introduzione di questo campo (nessun campo
# `type` salvato su disco): vedi `get_decrypted_passwords`, che continua a
# esporre solo i login, e `get_decrypted_items`, che espone tutti i tipi.
ITEM_TYPE_LOGIN = "login"
ITEM_TYPE_NOTE = "note"
ITEM_TYPE_CARD = "card"
VALID_ITEM_TYPES = frozenset({ITEM_TYPE_LOGIN, ITEM_TYPE_NOTE, ITEM_TYPE_CARD})

# Endpoint "Pwned Passwords" di Have I Been Pwned, usato con il modello
# k-anonymity: si contatta solo con il prefisso a 5 caratteri esadecimali
# dell'hash SHA-1 della password (vedi `check_password_breach`).
HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/{prefix}"
HIBP_USER_AGENT = "PasswordManagerPro-BreachCheck (k-anonymity client, no data retained)"


def _open_for_restricted_write(path: str, mode: str):
    """Apre `path` in scrittura creando il file (o troncando quello
    esistente) con permessi 0600, in modo che l'hash della master password e
    il materiale crittografico del vault non siano mai leggibili da altri
    utenti del sistema. Il parametro `mode` di `os.open` viene applicato dal
    sistema operativo solo quando il file viene creato ex novo: se esisteva
    già (es. un vault creato da una versione precedente dell'app, con
    permessi più larghi) i suoi permessi non cambierebbero da soli, quindi
    li forziamo esplicitamente con `fchmod` in ogni caso."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    if hasattr(os, "fchmod"):
        os.fchmod(fd, 0o600)
    return os.fdopen(fd, mode)

# Alfabeto ristretto (maiuscole + cifre, senza caratteri ambigui) usato per i
# codici di recovery: pensati per essere trascritti a mano, non digitati a
# macchina come una password normale.
RECOVERY_CODE_ALPHABET = "".join(
    c for c in string.ascii_uppercase + string.digits if c not in AMBIGUOUS_CHARACTERS
)
RECOVERY_CODE_BLOCK_COUNT = 5
RECOVERY_CODE_BLOCK_LENGTH = 4
KEY_MATERIAL_VERSION = 2


class VaultCorruptedError(Exception):
    """Il materiale crittografico del vault (`vault_key.json`) esiste ma non
    è utilizzabile per svelare la DEK con la master password corrente (JSON
    malformato, campo mancante, token Fernet non valido/manomesso). Non
    indica una password errata: `verify_master_password` (bcrypt) ha già
    superato il controllo prima che questo errore possa verificarsi."""


class PasswordManager:
    """
    Incapsula tutta la logica di gestione delle password.

    Modello delle chiavi (dalla v2 del formato dati):
    - Una Data Encryption Key (DEK) casuale cripta/decripta `passwords.json`.
      Non è mai derivata dalla master password: è generata con
      `Fernet.generate_key()` al primo sblocco riuscito del vault.
    - La DEK viene "avvolta" (wrapped, cioè criptata con Fernet) da due Key
      Encryption Key (KEK) indipendenti, entrambe derivate via PBKDF2 (stesso
      schema/iterazioni usati per la master password) ma da segreti e salt
      diversi:
        * la KEK "master", da master password + `kdf.salt` (invariato);
        * la KEK "recovery", da un codice di recovery ad alta entropia +
          un salt separato.
      Entrambe le versioni avvolte della DEK, il salt di recovery e l'hash
      bcrypt del codice di recovery vivono in `key_file` (default
      `vault_key.json` accanto a `db_file`). Il codice di recovery in chiaro
      non viene mai salvato su disco: è mostrato una sola volta al momento
      della generazione.
    - I vault creati prima di questa funzionalità (nessun `key_file`, dati
      criptati direttamente con la KEK master) vengono migrati
      automaticamente al primo sblocco riuscito: vedi `derive_and_set_cipher`.
    """

    def __init__(self, hash_file: str, salt_file: str, db_file: str, key_file: Optional[str] = None):
        self.hash_file = hash_file
        self.salt_file = salt_file
        self.db_file = db_file
        self.key_file = key_file or self._default_key_file(db_file)
        self.cipher_suite: Optional[Fernet] = None

    @staticmethod
    def _default_key_file(db_file: str) -> str:
        directory = os.path.dirname(db_file)
        return os.path.join(directory, "vault_key.json") if directory else "vault_key.json"

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
        with _open_for_restricted_write(self.hash_file, "wb") as f:
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
        with _open_for_restricted_write(self.salt_file, "wb") as f:
            f.write(salt)
        return salt

    def _derive_kek(self, secret: str, salt: bytes) -> bytes:
        """Deriva una Key Encryption Key Fernet da un segreto (master password
        o codice di recovery normalizzato) e un salt, con lo stesso schema
        PBKDF2-HMAC-SHA256 usato ovunque nel modulo."""
        key = hashlib.pbkdf2_hmac('sha256', secret.encode('utf-8'), salt, PBKDF2_ITERATIONS, dklen=32)
        return base64.urlsafe_b64encode(key)

    # --- Materiale crittografico del vault (DEK avvolta da due KEK) ---
    def _load_key_material(self) -> Optional[Dict[str, Any]]:
        if not os.path.exists(self.key_file):
            return None
        try:
            with open(self.key_file, "r") as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError):
            return None

    def _save_key_material(self, key_material: Dict[str, Any]) -> None:
        with _open_for_restricted_write(self.key_file, "w") as f:
            json.dump(key_material, f, indent=4)

    def _build_key_material(self, dek: bytes, master_kek: bytes) -> Tuple[Dict[str, Any], str]:
        """Costruisce il materiale crittografico completo per una DEK: la
        avvolge con la KEK master fornita e genera/avvolge un NUOVO codice di
        recovery. Non scrive nulla su disco (vedi `_save_key_material`);
        restituisce il materiale e il codice di recovery in chiaro, da
        mostrare una sola volta al chiamante."""
        recovery_code = generate_recovery_code()
        normalized_code = normalize_recovery_code(recovery_code)
        recovery_salt = os.urandom(16)
        recovery_kek = self._derive_kek(normalized_code, recovery_salt)

        key_material = {
            "version": KEY_MATERIAL_VERSION,
            "dek_wrapped_by_master": Fernet(master_kek).encrypt(dek).decode(),
            "recovery": {
                "salt": base64.b64encode(recovery_salt).decode(),
                "dek_wrapped_by_recovery": Fernet(recovery_kek).encrypt(dek).decode(),
                "code_hash": bcrypt.hashpw(normalized_code.encode('utf-8'), bcrypt.gensalt()).decode(),
            },
        }
        return key_material, recovery_code

    def derive_and_set_cipher(self, master_password: str, salt: bytes) -> Optional[str]:
        """Sblocca il vault con la master password: deriva la KEK master e la
        usa per svelare la DEK che cripta/decripta `passwords.json`.

        Se il vault non ha ancora materiale DEK salvato (`key_file`
        mancante), questo è il primo sblocco riuscito di questo vault: può
        trattarsi di un vault appena creato (database vuoto) oppure di un
        vault "legacy", creato prima di questa funzionalità, in cui i dati
        sono ancora criptati direttamente con la KEK master. In entrambi i
        casi viene generata ora una DEK, i dati esistenti (se presenti)
        vengono spostati sotto di essa, e viene emesso il primo codice di
        recovery.

        Restituisce il codice di recovery in chiaro SOLO quando è stato
        appena generato in questa chiamata (prima inizializzazione o
        migrazione); altrimenti None (sblocco "normale").
        """
        master_kek = self._derive_kek(master_password, salt)
        key_material = self._load_key_material()

        if key_material is not None:
            try:
                dek = Fernet(master_kek).decrypt(key_material["dek_wrapped_by_master"].encode())
            except Exception as exc:
                # `verify_master_password` (bcrypt) ha già superato il
                # controllo prima di arrivare qui: questo non è quindi un
                # caso di password errata, ma di vault_key.json corrotto,
                # illeggibile o modificato (JSON malformato, campo mancante,
                # token Fernet non valido). Segnalarlo con un tipo dedicato
                # invece di lasciar propagare l'eccezione originale evita che
                # un'interfaccia con la visualizzazione errori attiva (es.
                # Streamlit in sviluppo) mostri uno stack trace con path
                # assoluti del server nel browser dell'utente.
                raise VaultCorruptedError(
                    "Il materiale crittografico del vault (vault_key.json) è corrotto o illeggibile."
                ) from exc
            self.cipher_suite = Fernet(dek)
            return None

        legacy_db = self.load_encrypted_db()
        dek = Fernet.generate_key()
        dek_cipher = Fernet(dek)

        if legacy_db:
            legacy_cipher = Fernet(master_kek)
            migrated_db = {}
            for service, credentials in legacy_db.items():
                password_plain = legacy_cipher.decrypt(credentials['password_criptata'].encode()).decode()

                totp_encrypted = credentials.get("totp_secret_criptato") or ""
                totp_plain = legacy_cipher.decrypt(totp_encrypted.encode()).decode() if totp_encrypted else ""

                migrated_db[service] = {
                    "username": credentials['username'],
                    "password_criptata": dek_cipher.encrypt(password_plain.encode()).decode(),
                    "totp_secret_criptato": dek_cipher.encrypt(totp_plain.encode()).decode() if totp_plain else "",
                    "last_updated": credentials.get("last_updated"),
                }
            self.save_encrypted_db(migrated_db)

        new_key_material, recovery_code = self._build_key_material(dek, master_kek)
        self._save_key_material(new_key_material)
        self.cipher_suite = dek_cipher
        return recovery_code

    # --- Recovery della Master Password ---
    def verify_recovery_code(self, code: str) -> bool:
        """Verifica un codice di recovery contro l'hash bcrypt salvato, senza
        tentare di sbloccare la DEK: usato per dare un errore "codice errato"
        immediato e leggibile, prima ancora di chiedere una nuova master
        password."""
        key_material = self._load_key_material()
        if not key_material:
            return False
        recovery = key_material.get("recovery") or {}
        code_hash = recovery.get("code_hash")
        normalized = normalize_recovery_code(code or "")
        if not code_hash or not normalized:
            return False
        try:
            return bcrypt.checkpw(normalized.encode('utf-8'), code_hash.encode('utf-8'))
        except ValueError:
            return False

    def recover_with_code(self, code: str) -> Optional[bytes]:
        """Se il codice di recovery è corretto, sblocca e restituisce la DEK
        in chiaro (bytes, formato chiave Fernet), senza impostare
        `self.cipher_suite`: l'unico modo legittimo di ripristinare l'accesso
        è chiamare subito dopo `complete_recovery` con una nuova master
        password. Restituisce None se il codice è errato o il vault non ha
        materiale di recovery."""
        if not self.verify_recovery_code(code):
            return None
        key_material = self._load_key_material() or {}
        recovery = key_material.get("recovery") or {}
        try:
            recovery_salt = base64.b64decode(recovery["salt"])
            recovery_kek = self._derive_kek(normalize_recovery_code(code), recovery_salt)
            return Fernet(recovery_kek).decrypt(recovery["dek_wrapped_by_recovery"].encode())
        except Exception:
            return None

    def complete_recovery(self, dek: bytes, new_password: str) -> str:
        """Da chiamare subito dopo un `recover_with_code` andato a buon fine:
        imposta la nuova master password (l'utente l'ha dimenticata, quindi
        DEVE sceglierne una nuova), ri-avvolge la DEK esistente con la nuova
        KEK master (i dati restano quelli di sempre, nessuna ri-crittografia
        delle singole credenziali) e genera un NUOVO codice di recovery: il
        codice appena usato è a uso singolo e da questo momento non è più
        valido, perché il file di materiale crittografico viene interamente
        sovrascritto. Restituisce il nuovo codice in chiaro, da mostrare una
        sola volta."""
        self.set_master_hash(new_password)
        new_salt = self.generate_and_save_kdf_salt()
        new_master_kek = self._derive_kek(new_password, new_salt)

        key_material, new_recovery_code = self._build_key_material(dek, new_master_kek)
        self._save_key_material(key_material)
        self.cipher_suite = Fernet(dek)
        return new_recovery_code

    def regenerate_recovery_code(self, current_password: str) -> Optional[str]:
        """Genera un nuovo codice di recovery senza cambiare la master
        password: invalida il codice precedente (il file di materiale
        crittografico viene interamente sovrascritto, esattamente come in
        `complete_recovery`). Richiede la master password corrente come
        conferma esplicita, stesso principio di `change_master_password`.
        Restituisce None se la password è errata o il vault non è ancora nel
        formato con DEK (nessun login riuscito finora)."""
        if not self.verify_master_password(current_password):
            return None
        salt = self.load_kdf_salt()
        if not salt:
            return None
        key_material = self._load_key_material()
        if key_material is None:
            return None
        master_kek = self._derive_kek(current_password, salt)
        try:
            dek = Fernet(master_kek).decrypt(key_material["dek_wrapped_by_master"].encode())
        except Exception:
            return None
        new_key_material, new_code = self._build_key_material(dek, master_kek)
        self._save_key_material(new_key_material)
        return new_code

    # --- Gestione Database ---
    def load_encrypted_db(self) -> Dict[str, Any]:
        try:
            with open(self.db_file, "r") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def save_encrypted_db(self, data: Dict[str, Any]) -> None:
        with _open_for_restricted_write(self.db_file, "w") as f:
            json.dump(data, f, indent=4)

    def _decrypt_field(self, entry: Dict[str, Any], field: str) -> str:
        """Decripta un singolo campo cifrato di una voce del vault (stesso
        pattern usato per `password_criptata`/`totp_secret_criptato`),
        restituendo stringa vuota se il campo è assente o vuoto."""
        value = entry.get(field)
        if not value:
            return ""
        return self.cipher_suite.decrypt(value.encode()).decode()

    def get_decrypted_passwords(self) -> Optional[Dict[str, Dict[str, str]]]:
        """Restituisce SOLO le voci di tipo login (quelle senza campo `type`,
        cioè create prima dell'introduzione di note/carte, sono trattate come
        login per retrocompatibilità). Usato da Streamlit e dal frontend
        React per la vista "credenziali": entrambi devono continuare a vedere
        esattamente questo sottoinsieme del vault. Per TUTTE le voci (login +
        note + carte) vedi `get_decrypted_items`."""
        if not self.cipher_suite:
            return None

        encrypted_db = self.load_encrypted_db()
        decrypted_data = {}
        for service, credentials in encrypted_db.items():
            if credentials.get("type", ITEM_TYPE_LOGIN) != ITEM_TYPE_LOGIN:
                continue
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

    def add_credential(self, service: str, username: str, password: str, totp_secret: str = "",
                        tags: Optional[List[str]] = None) -> bool:
        """Aggiunge (o sovrascrive interamente) una voce di tipo login.

        `tags` è un parametro opzionale aggiunto in coda per non alterare la
        firma richiamabile posizionalmente da `ps_manager_app.py`, che non lo
        passa mai: se omesso (`None`), i tag di una voce già esistente con lo
        stesso nome vengono preservati invece di essere azzerati, così che
        modificare una credenziale da Streamlit non cancelli silenziosamente
        i tag assegnati dalla webapp React."""
        if not self.cipher_suite:
            return False

        encrypted_password = self.cipher_suite.encrypt(password.encode()).decode()

        encrypted_totp = ""
        if totp_secret:
            encrypted_totp = self.cipher_suite.encrypt(totp_secret.encode()).decode()

        db = self.load_encrypted_db()
        existing = db.get(service) or {}
        resolved_tags = tags if tags is not None else existing.get("tags", [])
        db[service] = {
            "type": ITEM_TYPE_LOGIN,
            "username": username,
            "password_criptata": encrypted_password,
            "last_updated": datetime.now().isoformat(),
            "totp_secret_criptato": encrypted_totp,
            "tags": normalize_tags(resolved_tags),
        }
        self.save_encrypted_db(db)
        return True

    def update_credential(self, service: str, new_username: str, new_password: str,
                           new_totp_secret: str = "", tags: Optional[List[str]] = None) -> bool:
        return self.add_credential(service, new_username, new_password, new_totp_secret, tags)

    def add_note(self, title: str, content: str, tags: Optional[List[str]] = None) -> bool:
        """Aggiunge (o sovrascrive interamente) una nota sicura: testo libero
        cifrato con la stessa DEK usata per le password. `tags` con lo stesso
        comportamento "preserva se omesso" di `add_credential`."""
        if not self.cipher_suite:
            return False

        db = self.load_encrypted_db()
        existing = db.get(title) or {}
        resolved_tags = tags if tags is not None else existing.get("tags", [])
        db[title] = {
            "type": ITEM_TYPE_NOTE,
            "content_criptato": self.cipher_suite.encrypt(content.encode()).decode(),
            "last_updated": datetime.now().isoformat(),
            "tags": normalize_tags(resolved_tags),
        }
        self.save_encrypted_db(db)
        return True

    def update_note(self, title: str, content: str, tags: Optional[List[str]] = None) -> bool:
        return self.add_note(title, content, tags)

    def add_card(self, name: str, cardholder: str, card_number: str, expiry: str, cvv: str,
                 tags: Optional[List[str]] = None) -> bool:
        """Aggiunge (o sovrascrive interamente) una carta di pagamento: ogni
        campo sensibile (intestatario, numero, scadenza, CVV) è cifrato
        singolarmente con la DEK, con lo stesso pattern usato per
        `password_criptata`/`totp_secret_criptato` - non un unico blob.
        `tags` con lo stesso comportamento "preserva se omesso" di
        `add_credential`."""
        if not self.cipher_suite:
            return False

        def encrypt_or_empty(value: str) -> str:
            return self.cipher_suite.encrypt(value.encode()).decode() if value else ""

        db = self.load_encrypted_db()
        existing = db.get(name) or {}
        resolved_tags = tags if tags is not None else existing.get("tags", [])
        db[name] = {
            "type": ITEM_TYPE_CARD,
            "cardholder_criptato": encrypt_or_empty(cardholder),
            "card_number_criptato": encrypt_or_empty(card_number),
            "expiry_criptato": encrypt_or_empty(expiry),
            "cvv_criptato": encrypt_or_empty(cvv),
            "last_updated": datetime.now().isoformat(),
            "tags": normalize_tags(resolved_tags),
        }
        self.save_encrypted_db(db)
        return True

    def update_card(self, name: str, cardholder: str, card_number: str, expiry: str, cvv: str,
                     tags: Optional[List[str]] = None) -> bool:
        return self.add_card(name, cardholder, card_number, expiry, cvv, tags)

    def get_decrypted_items(self) -> Optional[List[Dict[str, Any]]]:
        """Restituisce TUTTE le voci del vault (login, note, carte) con i
        campi decifrati appropriati al tipo. Usato SOLO dal backend della
        webapp React (mai da Streamlit, che resta su `get_decrypted_passwords`
        per vedere solo i login, esattamente come sempre)."""
        if not self.cipher_suite:
            return None

        encrypted_db = self.load_encrypted_db()
        items: List[Dict[str, Any]] = []
        for key, entry in encrypted_db.items():
            item_type = entry.get("type", ITEM_TYPE_LOGIN)
            base = {
                "key": key,
                "type": item_type,
                "tags": entry.get("tags") or [],
                "last_updated": entry.get("last_updated"),
            }
            try:
                if item_type == ITEM_TYPE_NOTE:
                    base["content"] = self._decrypt_field(entry, "content_criptato")
                elif item_type == ITEM_TYPE_CARD:
                    base["cardholder"] = self._decrypt_field(entry, "cardholder_criptato")
                    base["card_number"] = self._decrypt_field(entry, "card_number_criptato")
                    base["expiry"] = self._decrypt_field(entry, "expiry_criptato")
                    base["cvv"] = self._decrypt_field(entry, "cvv_criptato")
                else:
                    base["type"] = ITEM_TYPE_LOGIN
                    base["username"] = entry.get("username", "")
                    base["password"] = self._decrypt_field(entry, "password_criptata")
                    base["totp_secret"] = self._decrypt_field(entry, "totp_secret_criptato")
            except Exception:
                base["error"] = "ERRORE DI DECRIPTAZIONE"
            items.append(base)
        return items

    def delete_credential(self, service: str) -> None:
        """Elimina una voce del vault per chiave, indipendentemente dal tipo
        (login, nota o carta): la cancellazione è generica per costruzione,
        non serve un metodo dedicato per tipo."""
        db = self.load_encrypted_db()
        if service in db:
            del db[service]
            self.save_encrypted_db(db)

    def change_master_password(self, old_password: str, new_password: str) -> Tuple[bool, str]:
        """Cambia la master password. Grazie all'indirezione DEK/KEK, questa
        operazione NON deve più decriptare e ri-criptare ogni singola
        credenziale: si limita a ri-avvolgere la DEK esistente (invariata)
        con una nuova KEK master. Il comportamento osservabile resta
        identico a prima: dopo il cambio, tutte le credenziali restano
        leggibili con la nuova master password."""
        if not self.verify_master_password(old_password):
            return False, "La vecchia Master Password è errata."

        old_salt = self.load_kdf_salt()
        if not old_salt:
            return False, "File salt KDF non trovato. Annullamento."

        # Garantisce che il vault sia già nel formato con DEK: nessun effetto
        # se lo è già (è lo stesso percorso di migrazione automatica eseguito
        # ad ogni login riuscito), altrimenti migra ora un vault legacy.
        try:
            self.derive_and_set_cipher(old_password, old_salt)
        except Exception:
            return False, "Impossibile leggere i dati esistenti con la vecchia Master Password. Annullamento."

        key_material = self._load_key_material()
        if key_material is None:
            return False, "Materiale crittografico del vault non trovato. Annullamento."

        old_master_kek = self._derive_kek(old_password, old_salt)
        try:
            dek = Fernet(old_master_kek).decrypt(key_material["dek_wrapped_by_master"].encode())
        except Exception:
            return False, "Impossibile decriptare la chiave del vault con la vecchia Master Password."

        self.set_master_hash(new_password)
        new_salt = self.generate_and_save_kdf_salt()
        new_master_kek = self._derive_kek(new_password, new_salt)
        key_material["dek_wrapped_by_master"] = Fernet(new_master_kek).encrypt(dek).decode()
        self._save_key_material(key_material)

        self.cipher_suite = Fernet(dek)

        return True, "Master Password cambiata con successo!"


def normalize_tags(tags: Optional[List[str]]) -> List[str]:
    """Normalizza una lista di tag prima di salvarla: scarta valori non
    stringa, rimuove spazi superflui e voci vuote, deduplica preservando
    l'ordine di prima occorrenza (case-sensitive: "Lavoro" e "lavoro" restano
    tag distinti, come qualunque altro testo libero in questo modulo)."""
    if not tags:
        return []
    normalized: List[str] = []
    for tag in tags:
        if not isinstance(tag, str):
            continue
        cleaned = tag.strip()
        if cleaned and cleaned not in normalized:
            normalized.append(cleaned)
    return normalized


def generate_recovery_code() -> str:
    """Genera un codice di recovery casuale ad alta entropia (CSPRNG via
    `secrets`), in blocchi leggibili tipo 'XXXX-XXXX-XXXX-XXXX-XXXX' per
    facilitarne la trascrizione a mano. Alfabeto ristretto a maiuscole e
    cifre, senza caratteri ambigui (stesso criterio di `AMBIGUOUS_CHARACTERS`
    usato dal generatore di password)."""
    blocks = [
        "".join(secrets.choice(RECOVERY_CODE_ALPHABET) for _ in range(RECOVERY_CODE_BLOCK_LENGTH))
        for _ in range(RECOVERY_CODE_BLOCK_COUNT)
    ]
    return "-".join(blocks)


def normalize_recovery_code(code: str) -> str:
    """Canonicalizza un codice di recovery inserito dall'utente prima di
    derivarne la KEK o confrontarlo con l'hash salvato: rimuove trattini e
    spazi, converte in maiuscolo. Tollera formattazioni leggermente diverse
    da quella mostrata al momento della generazione (es. copia/incolla con
    spazi al posto dei trattini, minuscolo)."""
    if not code:
        return ""
    return "".join(ch for ch in code.strip().upper() if ch != "-" and not ch.isspace())


def check_password_breach(password: str, timeout: float = 5.0) -> Optional[int]:
    """Controlla se `password` compare in una violazione nota, usando l'API
    pubblica "Pwned Passwords" di Have I Been Pwned con il modello
    k-anonymity: si calcola l'hash SHA-1 della password solo in locale, e in
    rete viene inviato ESCLUSIVAMENTE il prefisso a 5 caratteri esadecimali
    di quell'hash (`GET /range/{prefix}`). L'API risponde con l'elenco dei
    suffissi hash che condividono quel prefisso (potenzialmente centinaia),
    ciascuno col relativo conteggio di violazioni; il confronto col suffisso
    della password reale avviene interamente in questo processo, mai in
    rete. Né la password in chiaro né il suo hash SHA-1 completo lasciano
    mai questa funzione.

    Restituisce il numero di violazioni note in cui compare la password (0
    se non risulta in nessuna) oppure `None` se il controllo non è riuscito
    (rete assente, timeout, risposta inattesa dall'API, ecc.). Questa
    funzione non solleva mai un'eccezione al chiamante: è un'operazione
    intrinsecamente inaffidabile perché dipende da un servizio di terze
    parti raggiungibile solo se c'è connettività di rete.
    """
    if not password:
        return 0

    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]

    request = urllib.request.Request(
        HIBP_RANGE_URL.format(prefix=prefix),
        headers={
            "User-Agent": HIBP_USER_AGENT,
            # Chiede all'API risposte "imbottite" con voci fittizie, una
            # mitigazione lato server contro l'analisi della dimensione della
            # risposta (documentata da HIBP); non richiede alcun dato
            # aggiuntivo da parte nostra.
            "Add-Padding": "true",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return None
    except Exception:
        # Qualunque altro imprevisto (encoding, risposta malformata, ecc.):
        # trattato come controllo non riuscito, mai come crash del chiamante.
        return None

    for line in body.splitlines():
        line_suffix, _, count_str = line.strip().partition(":")
        if line_suffix.strip().upper() != suffix:
            continue
        try:
            return int(count_str.strip())
        except ValueError:
            return None

    return 0


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
    """Valida la struttura di un database importato prima di sovrascrivere
    quello esistente. Copre tutti i tipi di voce del vault (login, note,
    carte): una voce senza campo `type` è trattata come login, esattamente
    come al caricamento normale (`get_decrypted_passwords`)."""
    if not isinstance(data, dict):
        return False, "Il file importato deve contenere un oggetto JSON (servizio -> credenziali)."

    for key, entry in data.items():
        if not isinstance(key, str) or not key:
            return False, "Trovato un nome di voce non valido."
        if not isinstance(entry, dict):
            return False, f"La voce '{key}' non è un oggetto valido."

        item_type = entry.get("type", ITEM_TYPE_LOGIN)
        if item_type not in VALID_ITEM_TYPES:
            return False, f"La voce '{key}' ha un campo 'type' con valore non riconosciuto."

        tags = entry.get("tags")
        if tags is not None and (not isinstance(tags, list) or not all(isinstance(t, str) for t in tags)):
            return False, f"La voce '{key}' ha un campo 'tags' con tipo non valido."

        last_updated = entry.get("last_updated")
        if last_updated is not None:
            if not isinstance(last_updated, str):
                return False, f"La voce '{key}' ha un campo 'last_updated' con tipo non valido."
            try:
                datetime.fromisoformat(last_updated)
            except ValueError:
                return False, f"La voce '{key}' ha un campo 'last_updated' con formato data non valido."

        if item_type == ITEM_TYPE_LOGIN:
            if "username" not in entry or "password_criptata" not in entry:
                return False, f"La voce '{key}' non contiene i campi obbligatori 'username' e 'password_criptata'."
            if not isinstance(entry["username"], str) or not isinstance(entry["password_criptata"], str):
                return False, f"La voce '{key}' ha campi 'username' o 'password_criptata' con tipo non valido."
            totp_secret_criptato = entry.get("totp_secret_criptato", "")
            if totp_secret_criptato and not isinstance(totp_secret_criptato, str):
                return False, f"La voce '{key}' ha un campo 'totp_secret_criptato' con tipo non valido."

        elif item_type == ITEM_TYPE_NOTE:
            if "content_criptato" not in entry:
                return False, f"La voce '{key}' non contiene il campo obbligatorio 'content_criptato'."
            if not isinstance(entry["content_criptato"], str):
                return False, f"La voce '{key}' ha un campo 'content_criptato' con tipo non valido."

        elif item_type == ITEM_TYPE_CARD:
            if "card_number_criptato" not in entry:
                return False, f"La voce '{key}' non contiene il campo obbligatorio 'card_number_criptato'."
            for field in ("card_number_criptato", "cardholder_criptato", "expiry_criptato", "cvv_criptato"):
                value = entry.get(field, "")
                if value and not isinstance(value, str):
                    return False, f"La voce '{key}' ha un campo '{field}' con tipo non valido."

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
