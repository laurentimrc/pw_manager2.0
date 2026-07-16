import pyotp
import pytest

from password_manager import (
    PasswordManager,
    generate_random_password,
    generate_totp_code,
    get_password_strength_feedback,
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
