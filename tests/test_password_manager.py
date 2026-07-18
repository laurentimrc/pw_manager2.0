import base64
import hashlib
import os
import urllib.error
from datetime import datetime
from unittest.mock import MagicMock, patch

import pyotp
import pytest
from cryptography.fernet import Fernet

from password_manager import (
    PBKDF2_ITERATIONS,
    PasswordManager,
    check_password_breach,
    compute_security_flags,
    generate_random_password,
    generate_recovery_code,
    generate_totp_code,
    get_password_strength_feedback,
    normalize_recovery_code,
    sort_credentials,
    validate_imported_db,
)


@pytest.fixture
def manager(tmp_path):
    hash_file = tmp_path / "master_pwd.hash"
    salt_file = tmp_path / "kdf.salt"
    db_file = tmp_path / "passwords.json"
    return PasswordManager(str(hash_file), str(salt_file), str(db_file))


def unlock(manager, password="Correct-Horse-Battery-Staple-1"):
    manager.set_master_hash(password)
    salt = manager.generate_and_save_kdf_salt()
    manager.derive_and_set_cipher(password, salt)
    return password


def unlock_with_recovery(manager, password="Correct-Horse-Battery-Staple-1"):
    """Come `unlock`, ma restituisce anche il codice di recovery generato al
    primo sblocco del vault (invece di scartarlo)."""
    manager.set_master_hash(password)
    salt = manager.generate_and_save_kdf_salt()
    recovery_code = manager.derive_and_set_cipher(password, salt)
    return password, recovery_code


def legacy_kek(password: str, salt: bytes) -> bytes:
    """Riproduce, indipendentemente dall'implementazione di PasswordManager,
    la derivazione della KEK master usata per criptare i vault creati PRIMA
    dell'introduzione della DEK: serve a costruire in questi test un vault
    "legacy" plausibile su cui verificare la migrazione automatica."""
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, PBKDF2_ITERATIONS, dklen=32)
    return base64.urlsafe_b64encode(key)


class TestMasterPassword:
    def test_no_hash_initially(self, manager):
        assert not manager.master_hash_exists()
        assert manager.load_master_hash() is None

    def test_set_and_verify_master_password(self, manager):
        manager.set_master_hash("MySecretPassword123!")
        assert manager.master_hash_exists()
        assert manager.verify_master_password("MySecretPassword123!")
        assert not manager.verify_master_password("WrongPassword")

    def test_verify_empty_password_fails(self, manager):
        manager.set_master_hash("MySecretPassword123!")
        assert not manager.verify_master_password("")


class TestCredentials:
    def test_add_and_decrypt_credential(self, manager):
        unlock(manager)
        manager.add_credential("GitHub", "octocat@example.com", "hunter2")

        decrypted = manager.get_decrypted_passwords()
        assert decrypted["GitHub"]["username"] == "octocat@example.com"
        assert decrypted["GitHub"]["password"] == "hunter2"

    def test_add_credential_with_totp(self, manager):
        unlock(manager)
        secret = pyotp.random_base32()
        manager.add_credential("GitHub", "octocat@example.com", "hunter2", secret)

        decrypted = manager.get_decrypted_passwords()
        assert decrypted["GitHub"]["totp_secret"] == secret

    def test_update_credential_overwrites_existing(self, manager):
        unlock(manager)
        manager.add_credential("GitHub", "old@example.com", "oldpass")
        manager.update_credential("GitHub", "new@example.com", "newpass")

        decrypted = manager.get_decrypted_passwords()
        assert decrypted["GitHub"]["username"] == "new@example.com"
        assert decrypted["GitHub"]["password"] == "newpass"

    def test_delete_credential(self, manager):
        unlock(manager)
        manager.add_credential("GitHub", "octocat@example.com", "hunter2")
        manager.delete_credential("GitHub")

        assert manager.get_decrypted_passwords() == {}

    def test_delete_nonexistent_credential_is_noop(self, manager):
        unlock(manager)
        manager.delete_credential("DoesNotExist")
        assert manager.get_decrypted_passwords() == {}

    def test_get_decrypted_passwords_without_cipher_returns_none(self, manager):
        assert manager.get_decrypted_passwords() is None

    def test_add_credential_without_cipher_fails(self, manager):
        assert manager.add_credential("GitHub", "user", "pass") is False


class TestChangeMasterPassword:
    def test_change_master_password_reencrypts_data(self, manager):
        old_password = unlock(manager)
        manager.add_credential("GitHub", "octocat@example.com", "hunter2")

        success, message = manager.change_master_password(old_password, "NewMasterPassword456!")
        assert success, message

        assert manager.verify_master_password("NewMasterPassword456!")
        assert not manager.verify_master_password(old_password)

        decrypted = manager.get_decrypted_passwords()
        assert decrypted["GitHub"]["password"] == "hunter2"

    def test_change_master_password_wrong_old_password_fails(self, manager):
        unlock(manager)
        success, message = manager.change_master_password("WrongOldPassword", "NewMasterPassword456!")
        assert not success

    def test_change_master_password_does_not_rotate_recovery_code(self, manager):
        old_password, recovery_code = unlock_with_recovery(manager)
        manager.add_credential("GitHub", "octocat@example.com", "hunter2")

        success, _ = manager.change_master_password(old_password, "NewMasterPassword456!")
        assert success

        # Il cambio della sola master password non invalida il codice di
        # recovery esistente: solo un utilizzo effettivo del recovery lo fa.
        assert manager.verify_recovery_code(recovery_code)


class TestRecoveryCodeGeneration:
    def test_generate_recovery_code_has_expected_shape(self):
        code = generate_recovery_code()
        blocks = code.split("-")
        assert len(blocks) == 5
        assert all(len(block) == 4 for block in blocks)

    def test_generate_recovery_code_excludes_ambiguous_characters(self):
        for _ in range(20):
            code = generate_recovery_code()
            assert not any(c in "IO10" for c in code)

    def test_generate_recovery_code_is_random(self):
        codes = {generate_recovery_code() for _ in range(25)}
        assert len(codes) == 25

    def test_normalize_recovery_code_strips_dashes_and_uppercases(self):
        assert normalize_recovery_code("abcd-efgh-ijkl-mnop-qrst") == "ABCDEFGHIJKLMNOPQRST"

    def test_normalize_recovery_code_tolerates_spaces_and_mixed_case(self):
        assert normalize_recovery_code(" AbCd efgh IJKL-mnop qrst ") == "ABCDEFGHIJKLMNOPQRST"

    def test_normalize_empty_code_returns_empty_string(self):
        assert normalize_recovery_code("") == ""


class TestVaultKeyAndRecovery:
    """Copre l'indirezione DEK/KEK: emissione del primo codice di recovery,
    sblocco tramite codice, e reset della master password dimenticata."""

    def test_first_unlock_generates_recovery_code_and_key_file(self, manager):
        _, recovery_code = unlock_with_recovery(manager)
        assert recovery_code
        assert manager.cipher_suite is not None
        assert os.path.exists(manager.key_file)

    def test_second_unlock_does_not_regenerate_recovery_code(self, manager):
        password, first_code = unlock_with_recovery(manager)
        assert first_code

        salt = manager.load_kdf_salt()
        second_code = manager.derive_and_set_cipher(password, salt)
        assert second_code is None

    def test_data_added_after_first_unlock_is_readable_on_relogin(self, manager):
        password, _ = unlock_with_recovery(manager)
        manager.add_credential("GitHub", "octocat@example.com", "hunter2")

        relogin_manager = PasswordManager(manager.hash_file, manager.salt_file, manager.db_file, manager.key_file)
        salt = relogin_manager.load_kdf_salt()
        recovery_code = relogin_manager.derive_and_set_cipher(password, salt)
        assert recovery_code is None  # nessuna nuova migrazione: già in formato DEK

        decrypted = relogin_manager.get_decrypted_passwords()
        assert decrypted["GitHub"]["password"] == "hunter2"

    def test_verify_recovery_code_accepts_correct_code_regardless_of_formatting(self, manager):
        _, recovery_code = unlock_with_recovery(manager)
        assert manager.verify_recovery_code(recovery_code)
        assert manager.verify_recovery_code(recovery_code.lower())
        assert manager.verify_recovery_code(recovery_code.replace("-", " "))

    def test_verify_recovery_code_rejects_wrong_code(self, manager):
        unlock_with_recovery(manager)
        assert not manager.verify_recovery_code("0000-0000-0000-0000-0000")

    def test_verify_recovery_code_without_vault_returns_false(self, manager):
        assert manager.verify_recovery_code("ANY-CODE-0000-0000-0000") is False

    def test_recover_with_correct_code_unlocks_dek(self, manager):
        _, recovery_code = unlock_with_recovery(manager)
        manager.add_credential("GitHub", "octocat@example.com", "hunter2")

        recovering_manager = PasswordManager(manager.hash_file, manager.salt_file, manager.db_file, manager.key_file)
        dek = recovering_manager.recover_with_code(recovery_code)
        assert dek is not None

        recovering_manager.cipher_suite = Fernet(dek)
        decrypted = recovering_manager.get_decrypted_passwords()
        assert decrypted["GitHub"]["password"] == "hunter2"

    def test_recover_with_wrong_code_returns_none(self, manager):
        unlock_with_recovery(manager)
        recovering_manager = PasswordManager(manager.hash_file, manager.salt_file, manager.db_file, manager.key_file)
        assert recovering_manager.recover_with_code("0000-0000-0000-0000-0000") is None

    def test_complete_recovery_sets_new_master_password_and_new_recovery_code(self, manager):
        old_password, recovery_code = unlock_with_recovery(manager)
        manager.add_credential("GitHub", "octocat@example.com", "hunter2")
        new_password = "Brand-New-Master-Pass-99!"

        recovering_manager = PasswordManager(manager.hash_file, manager.salt_file, manager.db_file, manager.key_file)
        dek = recovering_manager.recover_with_code(recovery_code)
        assert dek is not None
        new_recovery_code = recovering_manager.complete_recovery(dek, new_password)

        assert new_recovery_code
        assert new_recovery_code != recovery_code
        assert recovering_manager.verify_master_password(new_password)
        assert not recovering_manager.verify_master_password(old_password)

        # Le credenziali salvate prima del recovery restano leggibili con la
        # nuova master password, tramite un login "normale" successivo.
        login_manager = PasswordManager(manager.hash_file, manager.salt_file, manager.db_file, manager.key_file)
        salt = login_manager.load_kdf_salt()
        migration_code = login_manager.derive_and_set_cipher(new_password, salt)
        assert migration_code is None
        decrypted = login_manager.get_decrypted_passwords()
        assert decrypted["GitHub"]["password"] == "hunter2"

    def test_old_recovery_code_is_invalidated_after_use(self, manager):
        _, recovery_code = unlock_with_recovery(manager)

        recovering_manager = PasswordManager(manager.hash_file, manager.salt_file, manager.db_file, manager.key_file)
        dek = recovering_manager.recover_with_code(recovery_code)
        recovering_manager.complete_recovery(dek, "Another-New-Master-Pass-2!")

        assert not recovering_manager.verify_recovery_code(recovery_code)
        assert recovering_manager.recover_with_code(recovery_code) is None


class TestRegenerateRecoveryCode:
    """Copre la rigenerazione del codice di recovery a richiesta (senza
    cambiare la master password), disponibile in qualunque momento da
    autenticati - non solo al primo setup/migrazione."""

    def test_regenerate_returns_new_code_and_invalidates_old(self, manager):
        password, first_code = unlock_with_recovery(manager)

        new_code = manager.regenerate_recovery_code(password)

        assert new_code
        assert new_code != first_code
        assert manager.verify_recovery_code(new_code)
        assert not manager.verify_recovery_code(first_code)

    def test_regenerate_wrong_password_returns_none(self, manager):
        unlock_with_recovery(manager)
        assert manager.regenerate_recovery_code("WrongPassword") is None

    def test_regenerate_without_vault_returns_none(self, manager):
        assert manager.regenerate_recovery_code("AnyPassword") is None

    def test_regenerate_does_not_change_dek_or_data(self, manager):
        password, _ = unlock_with_recovery(manager)
        manager.add_credential("GitHub", "octocat@example.com", "hunter2")

        new_code = manager.regenerate_recovery_code(password)
        assert new_code

        # La DEK non cambia: le credenziali restano leggibili con la stessa
        # master password, nessuna ri-crittografia necessaria.
        decrypted = manager.get_decrypted_passwords()
        assert decrypted["GitHub"]["password"] == "hunter2"

    def test_new_code_can_recover_vault(self, manager):
        password, _ = unlock_with_recovery(manager)
        manager.add_credential("GitHub", "octocat@example.com", "hunter2")
        new_code = manager.regenerate_recovery_code(password)

        recovering_manager = PasswordManager(manager.hash_file, manager.salt_file, manager.db_file, manager.key_file)
        dek = recovering_manager.recover_with_code(new_code)
        assert dek is not None
        recovering_manager.cipher_suite = Fernet(dek)
        decrypted = recovering_manager.get_decrypted_passwords()
        assert decrypted["GitHub"]["password"] == "hunter2"


class TestLegacyVaultMigration:
    """Un vault creato PRIMA di questa funzionalità non ha `key_file`: i dati
    sono ancora criptati direttamente con la KEK master. La migrazione deve
    avvenire in modo trasparente al primo sblocco riuscito successivo."""

    def test_migrates_legacy_vault_on_first_unlock(self, manager):
        password = "Correct-Horse-Battery-Staple-1"
        manager.set_master_hash(password)
        salt = manager.generate_and_save_kdf_salt()

        old_cipher = Fernet(legacy_kek(password, salt))
        manager.save_encrypted_db({
            "GitHub": {
                "username": "octocat@example.com",
                "password_criptata": old_cipher.encrypt(b"hunter2").decode(),
                "totp_secret_criptato": "",
                "last_updated": "2024-01-01T00:00:00",
            }
        })
        assert not os.path.exists(manager.key_file)

        recovery_code = manager.derive_and_set_cipher(password, salt)

        assert recovery_code
        assert os.path.exists(manager.key_file)
        decrypted = manager.get_decrypted_passwords()
        assert decrypted["GitHub"]["password"] == "hunter2"
        assert decrypted["GitHub"]["username"] == "octocat@example.com"
        assert decrypted["GitHub"]["last_updated"] == "2024-01-01T00:00:00"

    def test_migrates_legacy_vault_with_totp_secret(self, manager):
        password = "Correct-Horse-Battery-Staple-1"
        manager.set_master_hash(password)
        salt = manager.generate_and_save_kdf_salt()

        old_cipher = Fernet(legacy_kek(password, salt))
        secret = pyotp.random_base32()
        manager.save_encrypted_db({
            "GitHub": {
                "username": "octocat@example.com",
                "password_criptata": old_cipher.encrypt(b"hunter2").decode(),
                "totp_secret_criptato": old_cipher.encrypt(secret.encode()).decode(),
                "last_updated": None,
            }
        })

        manager.derive_and_set_cipher(password, salt)
        decrypted = manager.get_decrypted_passwords()
        assert decrypted["GitHub"]["totp_secret"] == secret

    def test_migration_is_idempotent_on_subsequent_unlocks(self, manager):
        password = "Correct-Horse-Battery-Staple-1"
        manager.set_master_hash(password)
        salt = manager.generate_and_save_kdf_salt()

        old_cipher = Fernet(legacy_kek(password, salt))
        manager.save_encrypted_db({
            "GitHub": {
                "username": "a",
                "password_criptata": old_cipher.encrypt(b"hunter2").decode(),
                "totp_secret_criptato": "",
                "last_updated": None,
            }
        })

        first_code = manager.derive_and_set_cipher(password, salt)
        second_code = manager.derive_and_set_cipher(password, salt)
        assert first_code is not None
        assert second_code is None

    def test_migrates_legacy_vault_with_no_existing_credentials(self, manager):
        # Vault legacy "vuoto": master password e salt già impostati, ma
        # nessuna credenziale salvata ancora (nessun passwords.json).
        password = "Correct-Horse-Battery-Staple-1"
        manager.set_master_hash(password)
        salt = manager.generate_and_save_kdf_salt()

        recovery_code = manager.derive_and_set_cipher(password, salt)
        assert recovery_code
        assert manager.get_decrypted_passwords() == {}


class TestPasswordGenerator:
    def test_generate_random_password_respects_length(self):
        password = generate_random_password(20, True, True, True, True, True)
        assert len(password) == 20

    def test_generate_random_password_excludes_ambiguous_chars(self):
        for _ in range(20):
            password = generate_random_password(64, True, True, True, False, True)
            assert not any(c in "Il1O0|'`" for c in password)

    def test_generate_random_password_no_charset_returns_empty(self):
        assert generate_random_password(10, False, False, False, False, False) == ""

    def test_generate_random_password_length_shorter_than_guaranteed_sets(self):
        password = generate_random_password(2, True, True, True, True, False)
        assert len(password) == 2


class TestPasswordStrength:
    def test_empty_password_returns_defaults(self):
        text, feedback, score, color = get_password_strength_feedback("")
        assert text == "" and score == 0

    def test_strong_password_scores_high(self):
        _, _, score, _ = get_password_strength_feedback("Tr0ub4dor&3-correct-horse-battery")
        assert score >= 3


class TestCheckPasswordBreach:
    """Tutti i test qui mockano `urllib.request.urlopen`: nessuna chiamata di
    rete reale verso l'API di HIBP viene mai fatta durante la test suite."""

    @staticmethod
    def _mock_response(body: bytes) -> MagicMock:
        response = MagicMock()
        response.read.return_value = body
        response.__enter__.return_value = response
        response.__exit__.return_value = False
        return response

    def test_password_found_returns_breach_count(self):
        password = "password123"
        sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix, suffix = sha1_hash[:5], sha1_hash[5:]
        body = f"{suffix}:9999999\nFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:3\n".encode("utf-8")

        with patch("password_manager.urllib.request.urlopen",
                   return_value=self._mock_response(body)) as mock_urlopen:
            result = check_password_breach(password)

        assert result == 9999999
        # Verifica k-anonymity: nella richiesta viaggia solo il prefisso a 5
        # caratteri, mai l'hash completo né la password in chiaro.
        requested_url = mock_urlopen.call_args[0][0].full_url
        assert requested_url.endswith(f"/range/{prefix}")
        assert suffix not in requested_url
        assert password not in requested_url

    def test_password_not_found_returns_zero(self):
        password = "a-very-unique-high-entropy-password-987!"
        body = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:1\nBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB:2\n"

        with patch("password_manager.urllib.request.urlopen", return_value=self._mock_response(body)):
            result = check_password_breach(password)

        assert result == 0

    def test_network_error_returns_none_without_raising(self):
        with patch("password_manager.urllib.request.urlopen",
                   side_effect=urllib.error.URLError("nessuna connessione")):
            result = check_password_breach("qualunque-password")

        assert result is None

    def test_timeout_returns_none_without_raising(self):
        with patch("password_manager.urllib.request.urlopen", side_effect=TimeoutError("timeout")):
            result = check_password_breach("qualunque-password")

        assert result is None

    def test_empty_password_returns_zero_without_network_call(self):
        with patch("password_manager.urllib.request.urlopen") as mock_urlopen:
            result = check_password_breach("")

        assert result == 0
        mock_urlopen.assert_not_called()


class TestTotp:
    def test_generate_totp_code_returns_current_code(self):
        secret = pyotp.random_base32()
        code, remaining = generate_totp_code(secret)
        assert code == pyotp.TOTP(secret).now()
        assert 0 <= remaining <= 30

    def test_generate_totp_code_empty_secret(self):
        code, remaining = generate_totp_code("")
        assert code is None
        assert remaining == 0

    def test_generate_totp_code_invalid_secret_returns_errore(self):
        code, _ = generate_totp_code("not a valid base32 secret!!!")
        assert code == "Errore"


class TestValidateImportedDb:
    def test_valid_db_passes(self):
        data = {
            "GitHub": {"username": "user", "password_criptata": "enc"},
        }
        is_valid, error = validate_imported_db(data)
        assert is_valid
        assert error == ""

    def test_non_dict_root_fails(self):
        is_valid, _ = validate_imported_db(["not", "a", "dict"])
        assert not is_valid

    def test_missing_required_fields_fails(self):
        is_valid, _ = validate_imported_db({"GitHub": {"username": "user"}})
        assert not is_valid

    def test_non_dict_entry_fails(self):
        is_valid, _ = validate_imported_db({"GitHub": "not-a-dict"})
        assert not is_valid

    def test_wrong_field_types_fail(self):
        is_valid, _ = validate_imported_db({"GitHub": {"username": 123, "password_criptata": "enc"}})
        assert not is_valid

    def test_empty_db_is_valid(self):
        is_valid, _ = validate_imported_db({})
        assert is_valid

    def test_invalid_last_updated_format_fails(self):
        data = {
            "GitHub": {"username": "user", "password_criptata": "enc", "last_updated": "not-a-date"},
        }
        is_valid, _ = validate_imported_db(data)
        assert not is_valid

    def test_valid_last_updated_passes(self):
        data = {
            "GitHub": {"username": "user", "password_criptata": "enc", "last_updated": "2026-01-01T00:00:00"},
        }
        is_valid, _ = validate_imported_db(data)
        assert is_valid

    def test_invalid_totp_secret_type_fails(self):
        data = {
            "GitHub": {"username": "user", "password_criptata": "enc", "totp_secret_criptato": 123},
        }
        is_valid, _ = validate_imported_db(data)
        assert not is_valid


class TestSortCredentials:
    def test_sort_by_name(self):
        data = {
            "Zebra": {"password": "x"},
            "Amazon": {"password": "x"},
            "mango": {"password": "x"},
        }
        result = [service for service, _ in sort_credentials(data, "name")]
        assert result == ["Amazon", "mango", "Zebra"]

    def test_sort_by_recent(self):
        data = {
            "Old": {"last_updated": "2020-01-01T00:00:00"},
            "New": {"last_updated": "2026-01-01T00:00:00"},
            "NoDate": {},
        }
        result = [service for service, _ in sort_credentials(data, "recent")]
        assert result.index("New") < result.index("Old") < result.index("NoDate")

    def test_sort_by_weakest(self):
        data = {
            "Strong": {"password": "Tr0ub4dor&3-correct-horse-battery"},
            "Weak": {"password": "123456"},
            "Errored": {"password": "ERRORE DI DECRIPTAZIONE"},
        }
        result = [service for service, _ in sort_credentials(data, "weakest")]
        assert result.index("Weak") < result.index("Strong") < result.index("Errored")

    def test_default_sort_is_by_name(self):
        data = {"B": {"password": "x"}, "A": {"password": "x"}}
        result = [service for service, _ in sort_credentials(data)]
        assert result == ["A", "B"]


class TestComputeSecurityFlags:
    def test_weak_password_flagged(self):
        data = {"Weak": {"password": "123456"}}
        flags = compute_security_flags(data)
        assert "weak" in flags["Weak"]

    def test_strong_password_not_flagged_weak(self):
        data = {"Strong": {"password": "Tr0ub4dor&3-correct-horse-battery"}}
        flags = compute_security_flags(data)
        assert "weak" not in flags["Strong"]

    def test_reused_password_flagged_for_all_owners(self):
        data = {
            "A": {"password": "SamePassword123!"},
            "B": {"password": "SamePassword123!"},
            "C": {"password": "DifferentPassword456!"},
        }
        flags = compute_security_flags(data)
        assert "reused" in flags["A"]
        assert "reused" in flags["B"]
        assert "reused" not in flags["C"]

    def test_old_password_flagged(self):
        data = {"Old": {"password": "x", "last_updated": "2020-01-01T00:00:00"}}
        flags = compute_security_flags(data)
        assert "old" in flags["Old"]

    def test_recent_password_not_flagged_old(self):
        data = {"Recent": {"password": "x", "last_updated": datetime.now().isoformat()}}
        flags = compute_security_flags(data)
        assert "old" not in flags["Recent"]

    def test_malformed_last_updated_does_not_crash(self):
        data = {"Broken": {"password": "x", "last_updated": "not-a-date"}}
        flags = compute_security_flags(data)
        assert "old" not in flags["Broken"]

    def test_error_password_not_flagged_weak_or_reused(self):
        data = {
            "A": {"password": "ERRORE DI DECRIPTAZIONE"},
            "B": {"password": "ERRORE DI DECRIPTAZIONE"},
        }
        flags = compute_security_flags(data)
        assert flags["A"] == []
        assert flags["B"] == []
