import time
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app

MASTER_PASSWORD = "Correct-Horse-Battery-Staple-1"


def make_client(tmp_path, **overrides) -> TestClient:
    settings = Settings(
        hash_file=str(tmp_path / "master_pwd.hash"),
        salt_file=str(tmp_path / "kdf.salt"),
        db_file=str(tmp_path / "passwords.json"),
        cors_origins=["http://127.0.0.1:5173"],
        **overrides,
    )
    app = create_app(settings)
    return TestClient(app)


def setup_and_login(client: TestClient, password: str = MASTER_PASSWORD) -> None:
    resp = client.post("/api/auth/setup", json={"new_password": password, "confirm_password": password})
    assert resp.status_code == 200, resp.text


class TestAuthSetupAndLogin:
    def test_status_reports_setup_required_initially(self, tmp_path):
        client = make_client(tmp_path)
        resp = client.get("/api/auth/status")
        assert resp.status_code == 200
        body = resp.json()
        assert body["setup_required"] is True
        assert body["authenticated"] is False

    def test_setup_creates_session_and_authenticates(self, tmp_path):
        client = make_client(tmp_path)
        setup_and_login(client)
        status = client.get("/api/auth/status").json()
        assert status["setup_required"] is False
        assert status["authenticated"] is True
        assert "pwm_session" in client.cookies

    def test_setup_returns_recovery_code_once(self, tmp_path):
        client = make_client(tmp_path)
        resp = client.post("/api/auth/setup", json={
            "new_password": MASTER_PASSWORD, "confirm_password": MASTER_PASSWORD,
        })
        assert resp.status_code == 200
        body = resp.json()
        assert body["recovery_code"]
        assert len(body["recovery_code"].split("-")) == 5

    def test_login_after_setup_does_not_return_a_new_recovery_code(self, tmp_path):
        client = make_client(tmp_path)
        setup_and_login(client)
        client.cookies.clear()
        resp = client.post("/api/auth/login", json={"password": MASTER_PASSWORD})
        assert resp.status_code == 200
        assert resp.json()["recovery_code"] is None

    def test_setup_rejects_short_password(self, tmp_path):
        client = make_client(tmp_path)
        resp = client.post("/api/auth/setup", json={"new_password": "short", "confirm_password": "short"})
        assert resp.status_code == 400

    def test_setup_rejects_mismatched_confirmation(self, tmp_path):
        client = make_client(tmp_path)
        resp = client.post("/api/auth/setup", json={
            "new_password": MASTER_PASSWORD, "confirm_password": "Different-Password-123!"
        })
        assert resp.status_code == 400

    def test_setup_twice_fails(self, tmp_path):
        client = make_client(tmp_path)
        setup_and_login(client)
        resp = client.post("/api/auth/setup", json={
            "new_password": MASTER_PASSWORD, "confirm_password": MASTER_PASSWORD
        })
        assert resp.status_code == 409

    def test_login_with_correct_password_succeeds(self, tmp_path):
        client = make_client(tmp_path)
        setup_and_login(client)
        client.cookies.clear()
        resp = client.post("/api/auth/login", json={"password": MASTER_PASSWORD})
        assert resp.status_code == 200
        assert resp.json()["authenticated"] is True

    def test_login_with_wrong_password_fails(self, tmp_path):
        client = make_client(tmp_path)
        setup_and_login(client)
        client.cookies.clear()
        resp = client.post("/api/auth/login", json={"password": "WrongPassword"})
        assert resp.status_code == 401
        assert resp.json()["detail"]["remaining_attempts"] == 4

    def test_logout_clears_session(self, tmp_path):
        client = make_client(tmp_path)
        setup_and_login(client)
        resp = client.post("/api/auth/logout")
        assert resp.status_code == 200
        status = client.get("/api/auth/status").json()
        assert status["authenticated"] is False

    def test_protected_endpoint_requires_session(self, tmp_path):
        client = make_client(tmp_path)
        resp = client.get("/api/credentials")
        assert resp.status_code == 401


class TestLoginLockout:
    def test_lockout_after_max_attempts_then_recovers(self, tmp_path):
        # lockout_seconds abbastanza ampio da assorbire l'overhead di bcrypt/PBKDF2
        # dei tentativi di login precedenti (altrimenti il cooldown scadrebbe da solo).
        client = make_client(tmp_path, max_login_attempts=3, lockout_seconds=5)
        setup_and_login(client)
        client.cookies.clear()

        for _ in range(2):
            resp = client.post("/api/auth/login", json={"password": "wrong"})
            assert resp.status_code == 401

        resp = client.post("/api/auth/login", json={"password": "wrong"})
        assert resp.status_code == 423
        assert resp.json()["detail"]["code"] == "locked_out"

        # Bloccato anche con la password corretta durante il cooldown.
        resp = client.post("/api/auth/login", json={"password": MASTER_PASSWORD})
        assert resp.status_code == 423

        time.sleep(5.2)
        resp = client.post("/api/auth/login", json={"password": MASTER_PASSWORD})
        assert resp.status_code == 200


class TestSessionTimeout:
    def test_session_expires_after_inactivity(self, tmp_path):
        client = make_client(tmp_path, session_timeout_seconds=1)
        setup_and_login(client)
        time.sleep(1.2)
        resp = client.get("/api/credentials")
        assert resp.status_code == 401
        assert resp.json()["detail"]["code"] == "session_expired"


class TestVaultCorruption:
    """Un vault_key.json corrotto/manomesso deve produrre un errore pulito
    e intenzionale (VaultCorruptedError -> 500 con un messaggio chiaro), non
    un'eccezione grezza non gestita che finisce nell'handler generico di
    FastAPI."""

    def test_login_with_corrupted_key_file_returns_clean_error(self, tmp_path):
        client = make_client(tmp_path)
        setup_and_login(client)
        client.cookies.clear()

        key_file = tmp_path / "vault_key.json"
        key_file.write_text('{"version": 2, "dek_wrapped_by_master": "not-a-valid-fernet-token"}')

        resp = client.post("/api/auth/login", json={"password": MASTER_PASSWORD})
        assert resp.status_code == 500
        # Il messaggio deve restare quello intenzionale che abbiamo scritto,
        # non un dump generico né uno stack trace.
        assert "corrotto" in resp.text.lower()
        assert "Traceback" not in resp.text
        assert str(tmp_path) not in resp.text

    def test_setup_with_preexisting_corrupted_key_file_returns_clean_error(self, tmp_path):
        key_file = tmp_path / "vault_key.json"
        key_file.write_text('{"version": 2, "dek_wrapped_by_master": "not-a-valid-fernet-token"}')

        client = make_client(tmp_path)
        resp = client.post("/api/auth/setup", json={
            "new_password": MASTER_PASSWORD, "confirm_password": MASTER_PASSWORD,
        })
        assert resp.status_code == 500
        assert "corrotto" in resp.text.lower()
        assert "Traceback" not in resp.text


class TestCredentialsCrud:
    def _authed_client(self, tmp_path) -> TestClient:
        client = make_client(tmp_path)
        setup_and_login(client)
        return client

    def test_add_list_and_get_secret(self, tmp_path):
        client = self._authed_client(tmp_path)
        resp = client.post("/api/credentials", json={
            "service": "GitHub", "username": "octocat@example.com", "password": "hunter2-strong-Passw0rd!",
        })
        assert resp.status_code == 201

        resp = client.get("/api/credentials")
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert len(items) == 1
        assert items[0]["service"] == "GitHub"
        assert "password" not in items[0]

        resp = client.get("/api/credentials/GitHub/secret")
        assert resp.status_code == 200
        assert resp.json()["password"] == "hunter2-strong-Passw0rd!"

    def test_add_duplicate_service_fails(self, tmp_path):
        client = self._authed_client(tmp_path)
        client.post("/api/credentials", json={"service": "GitHub", "username": "a", "password": "aaaaaaaaaaaa"})
        resp = client.post("/api/credentials", json={"service": "GitHub", "username": "b", "password": "bbbbbbbbbbbb"})
        assert resp.status_code == 409

    def test_update_credential(self, tmp_path):
        client = self._authed_client(tmp_path)
        client.post("/api/credentials", json={"service": "GitHub", "username": "old", "password": "oldpassword123"})
        resp = client.put("/api/credentials/GitHub", json={"username": "new", "password": "newpassword456"})
        assert resp.status_code == 200
        secret = client.get("/api/credentials/GitHub/secret").json()
        assert secret["username"] == "new"
        assert secret["password"] == "newpassword456"

    def test_update_nonexistent_service_fails(self, tmp_path):
        client = self._authed_client(tmp_path)
        resp = client.put("/api/credentials/DoesNotExist", json={"username": "a", "password": "aaaaaaaaaaaa"})
        assert resp.status_code == 404

    def test_delete_credential(self, tmp_path):
        client = self._authed_client(tmp_path)
        client.post("/api/credentials", json={"service": "GitHub", "username": "a", "password": "aaaaaaaaaaaa"})
        resp = client.delete("/api/credentials/GitHub")
        assert resp.status_code == 200
        assert client.get("/api/credentials").json()["items"] == []

    def test_delete_nonexistent_service_fails(self, tmp_path):
        client = self._authed_client(tmp_path)
        resp = client.delete("/api/credentials/DoesNotExist")
        assert resp.status_code == 404

    def test_search_filters_by_service_name(self, tmp_path):
        client = self._authed_client(tmp_path)
        client.post("/api/credentials", json={"service": "GitHub", "username": "a", "password": "aaaaaaaaaaaa"})
        client.post("/api/credentials", json={"service": "Amazon", "username": "b", "password": "bbbbbbbbbbbb"})
        resp = client.get("/api/credentials", params={"search": "git"})
        items = resp.json()["items"]
        assert len(items) == 1
        assert items[0]["service"] == "GitHub"

    def test_credential_with_totp_secret_exposes_code(self, tmp_path):
        import pyotp
        client = self._authed_client(tmp_path)
        secret = pyotp.random_base32()
        client.post("/api/credentials", json={
            "service": "GitHub", "username": "a", "password": "aaaaaaaaaaaa", "totp_secret": secret,
        })
        items = client.get("/api/credentials").json()["items"]
        assert items[0]["has_totp"] is True

        resp = client.get("/api/credentials/GitHub/totp")
        assert resp.status_code == 200
        body = resp.json()
        assert body["code"] == pyotp.TOTP(secret).now()
        assert 0 <= body["remaining"] <= 30

    def test_totp_endpoint_without_secret_fails(self, tmp_path):
        client = self._authed_client(tmp_path)
        client.post("/api/credentials", json={"service": "GitHub", "username": "a", "password": "aaaaaaaaaaaa"})
        resp = client.get("/api/credentials/GitHub/totp")
        assert resp.status_code == 400


class TestSecurityDashboard:
    def test_dashboard_counts_weak_reused_and_old(self, tmp_path):
        client = make_client(tmp_path)
        setup_and_login(client)
        client.post("/api/credentials", json={"service": "A", "username": "a", "password": "SamePassword123!"})
        client.post("/api/credentials", json={"service": "B", "username": "b", "password": "SamePassword123!"})
        client.post("/api/credentials", json={"service": "C", "username": "c", "password": "123456"})

        resp = client.get("/api/security/dashboard")
        assert resp.status_code == 200
        body = resp.json()
        assert body["total_credentials"] == 3
        assert body["reused_count"] == 1
        assert body["weak_count"] >= 1


class TestBreachCheck:
    """`check_password_breach` viene sempre mockato a livello di dominio: non
    serve (e non si deve) contattare l'HIBP reale per testare l'endpoint."""

    def test_single_credential_requires_authentication(self, tmp_path):
        client = make_client(tmp_path)
        resp = client.post("/api/credentials/GitHub/breach-check")
        assert resp.status_code == 401

    def test_single_credential_reports_breach_count(self, tmp_path):
        client = make_client(tmp_path)
        setup_and_login(client)
        client.post("/api/credentials", json={"service": "GitHub", "username": "a", "password": "hunter2-Strong!"})

        with patch("app.main.check_password_breach", return_value=42) as mocked:
            resp = client.post("/api/credentials/GitHub/breach-check")
        assert resp.status_code == 200
        body = resp.json()
        assert body["service"] == "GitHub"
        assert body["breach_count"] == 42
        assert body["checked"] is True
        # La password decriptata viene passata alla funzione di dominio, ma
        # non deve mai comparire nella risposta HTTP al frontend.
        mocked.assert_called_once_with("hunter2-Strong!")
        assert "password" not in body
        assert "hunter2-Strong!" not in resp.text

    def test_single_credential_not_found(self, tmp_path):
        client = make_client(tmp_path)
        setup_and_login(client)
        with patch("app.main.check_password_breach") as mocked:
            resp = client.post("/api/credentials/DoesNotExist/breach-check")
        assert resp.status_code == 404
        mocked.assert_not_called()

    def test_single_credential_network_failure_is_reported_distinctly(self, tmp_path):
        client = make_client(tmp_path)
        setup_and_login(client)
        client.post("/api/credentials", json={"service": "GitHub", "username": "a", "password": "hunter2-Strong!"})

        with patch("app.main.check_password_breach", return_value=None):
            resp = client.post("/api/credentials/GitHub/breach-check")
        assert resp.status_code == 200
        body = resp.json()
        assert body["breach_count"] is None
        assert body["checked"] is False

    def test_bulk_check_requires_authentication(self, tmp_path):
        client = make_client(tmp_path)
        resp = client.post("/api/security/breach-check")
        assert resp.status_code == 401

    def test_bulk_check_deduplicates_identical_passwords(self, tmp_path):
        client = make_client(tmp_path)
        setup_and_login(client)
        client.post("/api/credentials", json={"service": "A", "username": "a", "password": "SamePassword123!"})
        client.post("/api/credentials", json={"service": "B", "username": "b", "password": "SamePassword123!"})
        client.post("/api/credentials", json={"service": "C", "username": "c", "password": "DifferentPass456!"})

        with patch("app.main.check_password_breach", return_value=7) as mocked:
            resp = client.post("/api/security/breach-check")
        assert resp.status_code == 200
        # Una sola chiamata di rete per la password condivisa da A e B, una
        # per quella di C: due chiamate in totale, non tre.
        assert mocked.call_count == 2
        results = {r["service"]: r for r in resp.json()["results"]}
        assert results["A"]["breach_count"] == 7
        assert results["B"]["breach_count"] == 7
        assert results["C"]["breach_count"] == 7
        assert all(r["checked"] for r in results.values())

    def test_bulk_check_partial_failure_does_not_block_other_results(self, tmp_path):
        client = make_client(tmp_path)
        setup_and_login(client)
        client.post("/api/credentials", json={"service": "A", "username": "a", "password": "PasswordOne123!"})
        client.post("/api/credentials", json={"service": "B", "username": "b", "password": "PasswordTwo456!"})

        def fake_check(password: str):
            return None if password == "PasswordOne123!" else 3

        with patch("app.main.check_password_breach", side_effect=fake_check):
            resp = client.post("/api/security/breach-check")
        assert resp.status_code == 200
        results = {r["service"]: r for r in resp.json()["results"]}
        assert results["A"]["checked"] is False
        assert results["A"]["breach_count"] is None
        assert results["B"]["checked"] is True
        assert results["B"]["breach_count"] == 3


class TestUtility:
    def test_export_returns_encrypted_db(self, tmp_path):
        client = make_client(tmp_path)
        setup_and_login(client)
        client.post("/api/credentials", json={"service": "GitHub", "username": "a", "password": "aaaaaaaaaaaa"})
        resp = client.get("/api/utility/export")
        assert resp.status_code == 200
        body = resp.json()
        assert "GitHub" in body
        assert body["GitHub"]["password_criptata"] != "aaaaaaaaaaaa"

    def test_import_requires_confirmation(self, tmp_path):
        client = make_client(tmp_path)
        setup_and_login(client)
        client.post("/api/credentials", json={"service": "GitHub", "username": "a", "password": "aaaaaaaaaaaa"})
        export_data = client.get("/api/utility/export").json()
        resp = client.post("/api/utility/import", json={"data": export_data, "confirm": False})
        assert resp.status_code == 400
        detail = resp.json()["detail"]
        assert detail["code"] == "confirmation_required"
        assert detail["entries"] == 1

    def test_import_valid_backup_replaces_db(self, tmp_path):
        client = make_client(tmp_path)
        setup_and_login(client)
        client.post("/api/credentials", json={"service": "GitHub", "username": "a", "password": "aaaaaaaaaaaa"})
        backup = client.get("/api/utility/export").json()

        client.post("/api/credentials", json={"service": "Extra", "username": "x", "password": "xxxxxxxxxxxx"})
        resp = client.post("/api/utility/import", json={"data": backup, "confirm": True})
        assert resp.status_code == 200

        items = client.get("/api/credentials").json()["items"]
        assert [item["service"] for item in items] == ["GitHub"]

    def test_import_invalid_backup_rejected(self, tmp_path):
        client = make_client(tmp_path)
        setup_and_login(client)
        resp = client.post("/api/utility/import", json={"data": {"Bad": {"foo": "bar"}}, "confirm": True})
        assert resp.status_code == 400

    def test_change_master_password_success_and_data_reencrypted(self, tmp_path):
        client = make_client(tmp_path)
        setup_and_login(client)
        client.post("/api/credentials", json={"service": "GitHub", "username": "a", "password": "hunter2-Strong!"})

        new_password = "Another-Strong-Master-Pass-2!"
        resp = client.post("/api/utility/change-master-password", json={
            "old_password": MASTER_PASSWORD, "new_password": new_password, "confirm_password": new_password,
        })
        assert resp.status_code == 200

        # La sessione corrente resta valida e usa la nuova password/cipher.
        secret = client.get("/api/credentials/GitHub/secret")
        assert secret.status_code == 200
        assert secret.json()["password"] == "hunter2-Strong!"

        # Login con la vecchia password ora fallisce, con la nuova funziona.
        client.cookies.clear()
        resp = client.post("/api/auth/login", json={"password": MASTER_PASSWORD})
        assert resp.status_code == 401
        resp = client.post("/api/auth/login", json={"password": new_password})
        assert resp.status_code == 200

    def test_change_master_password_wrong_old_password_fails(self, tmp_path):
        client = make_client(tmp_path)
        setup_and_login(client)
        resp = client.post("/api/utility/change-master-password", json={
            "old_password": "WrongOldPassword",
            "new_password": "Another-Strong-Master-Pass-2!",
            "confirm_password": "Another-Strong-Master-Pass-2!",
        })
        assert resp.status_code == 400


class TestRecovery:
    def _setup_and_get_recovery_code(self, tmp_path) -> tuple:
        client = make_client(tmp_path)
        resp = client.post("/api/auth/setup", json={
            "new_password": MASTER_PASSWORD, "confirm_password": MASTER_PASSWORD,
        })
        recovery_code = resp.json()["recovery_code"]
        client.post("/api/credentials", json={
            "service": "GitHub", "username": "octocat@example.com", "password": "hunter2-Strong!",
        })
        return client, recovery_code

    def test_recover_requires_existing_vault(self, tmp_path):
        client = make_client(tmp_path)
        resp = client.post("/api/auth/recover/verify", json={"recovery_code": "AAAA-AAAA-AAAA-AAAA-AAAA"})
        assert resp.status_code == 409

    def test_verify_correct_recovery_code_succeeds(self, tmp_path):
        client, recovery_code = self._setup_and_get_recovery_code(tmp_path)
        resp = client.post("/api/auth/recover/verify", json={"recovery_code": recovery_code})
        assert resp.status_code == 200
        assert resp.json()["valid"] is True

    def test_verify_wrong_recovery_code_gives_clear_error(self, tmp_path):
        client, _ = self._setup_and_get_recovery_code(tmp_path)
        resp = client.post("/api/auth/recover/verify", json={"recovery_code": "0000-0000-0000-0000-0000"})
        assert resp.status_code == 400
        detail = resp.json()["detail"]
        assert detail["code"] == "invalid_recovery_code"

    def test_recover_with_wrong_code_fails_without_crashing(self, tmp_path):
        client, _ = self._setup_and_get_recovery_code(tmp_path)
        resp = client.post("/api/auth/recover", json={
            "recovery_code": "0000-0000-0000-0000-0000",
            "new_password": "Brand-New-Master-Pass-99!",
            "confirm_password": "Brand-New-Master-Pass-99!",
        })
        assert resp.status_code == 400
        assert resp.json()["detail"]["code"] == "invalid_recovery_code"

    def test_recover_with_weak_new_password_is_rejected(self, tmp_path):
        client, recovery_code = self._setup_and_get_recovery_code(tmp_path)
        resp = client.post("/api/auth/recover", json={
            "recovery_code": recovery_code, "new_password": "short", "confirm_password": "short",
        })
        assert resp.status_code == 400

    def test_recover_with_mismatched_confirmation_is_rejected(self, tmp_path):
        client, recovery_code = self._setup_and_get_recovery_code(tmp_path)
        resp = client.post("/api/auth/recover", json={
            "recovery_code": recovery_code,
            "new_password": "Brand-New-Master-Pass-99!",
            "confirm_password": "Different-Pass-2!",
        })
        assert resp.status_code == 400

    def test_full_recovery_flow_resets_password_and_keeps_data_readable(self, tmp_path):
        client, recovery_code = self._setup_and_get_recovery_code(tmp_path)
        new_password = "Brand-New-Master-Pass-99!"

        resp = client.post("/api/auth/recover", json={
            "recovery_code": recovery_code, "new_password": new_password, "confirm_password": new_password,
        })
        assert resp.status_code == 200
        new_recovery_code = resp.json()["recovery_code"]
        assert new_recovery_code
        assert new_recovery_code != recovery_code

        # Il vecchio codice di recovery non è più valido (uso singolo).
        resp = client.post("/api/auth/recover/verify", json={"recovery_code": recovery_code})
        assert resp.status_code == 400

        # La vecchia Master Password non funziona più, la nuova sì, e i dati
        # inseriti prima del recovery sono ancora leggibili.
        client.cookies.clear()
        resp = client.post("/api/auth/login", json={"password": MASTER_PASSWORD})
        assert resp.status_code == 401
        resp = client.post("/api/auth/login", json={"password": new_password})
        assert resp.status_code == 200
        assert resp.json()["recovery_code"] is None

        secret = client.get("/api/credentials/GitHub/secret")
        assert secret.status_code == 200
        assert secret.json()["password"] == "hunter2-Strong!"


class TestRecoveryLockout:
    """Il codice di recovery ha entropia molto alta, ma il guard esiste
    comunque per difesa in profondità: nessun contatore su un endpoint che
    tenta di indovinare un segreto è un gap, indipendentemente da quanto sia
    difficile indovinarlo in pratica."""

    def _setup(self, tmp_path, **overrides):
        client = make_client(tmp_path, **overrides)
        resp = client.post("/api/auth/setup", json={
            "new_password": MASTER_PASSWORD, "confirm_password": MASTER_PASSWORD,
        })
        return client, resp.json()["recovery_code"]

    def test_verify_locks_out_after_max_attempts(self, tmp_path):
        client, _ = self._setup(tmp_path, max_login_attempts=3, lockout_seconds=5)

        for _ in range(2):
            resp = client.post("/api/auth/recover/verify", json={"recovery_code": "0000-0000-0000-0000-0000"})
            assert resp.status_code == 400

        resp = client.post("/api/auth/recover/verify", json={"recovery_code": "0000-0000-0000-0000-0000"})
        assert resp.status_code == 423
        assert resp.json()["detail"]["code"] == "locked_out"

    def test_lockout_blocks_the_correct_code_too(self, tmp_path):
        client, recovery_code = self._setup(tmp_path, max_login_attempts=3, lockout_seconds=5)
        for _ in range(3):
            client.post("/api/auth/recover/verify", json={"recovery_code": "0000-0000-0000-0000-0000"})

        resp = client.post("/api/auth/recover/verify", json={"recovery_code": recovery_code})
        assert resp.status_code == 423

    def test_lockout_is_shared_between_verify_and_complete_endpoints(self, tmp_path):
        # Un attaccante non deve poter aggirare il lockout distribuendo i
        # tentativi tra i due endpoint di recovery.
        client, _ = self._setup(tmp_path, max_login_attempts=3, lockout_seconds=5)

        resp = client.post("/api/auth/recover/verify", json={"recovery_code": "0000-0000-0000-0000-0000"})
        assert resp.status_code == 400
        resp = client.post("/api/auth/recover", json={
            "recovery_code": "0000-0000-0000-0000-0000",
            "new_password": "Brand-New-Master-Pass-99!",
            "confirm_password": "Brand-New-Master-Pass-99!",
        })
        assert resp.status_code == 400

        resp = client.post("/api/auth/recover/verify", json={"recovery_code": "0000-0000-0000-0000-0000"})
        assert resp.status_code == 423
        assert resp.json()["detail"]["code"] == "locked_out"

    def test_successful_verify_resets_the_guard(self, tmp_path):
        client, recovery_code = self._setup(tmp_path, max_login_attempts=3, lockout_seconds=5)

        resp = client.post("/api/auth/recover/verify", json={"recovery_code": "0000-0000-0000-0000-0000"})
        assert resp.status_code == 400
        resp = client.post("/api/auth/recover/verify", json={"recovery_code": recovery_code})
        assert resp.status_code == 200

        # Il contatore è stato azzerato dal tentativo riuscito: altri due
        # tentativi falliti non bloccano ancora (servirebbe un terzo).
        for _ in range(2):
            resp = client.post("/api/auth/recover/verify", json={"recovery_code": "0000-0000-0000-0000-0000"})
            assert resp.status_code == 400

    def test_recover_locks_out_after_max_attempts(self, tmp_path):
        client, _ = self._setup(tmp_path, max_login_attempts=3, lockout_seconds=5)

        for _ in range(3):
            resp = client.post("/api/auth/recover", json={
                "recovery_code": "0000-0000-0000-0000-0000",
                "new_password": "Brand-New-Master-Pass-99!",
                "confirm_password": "Brand-New-Master-Pass-99!",
            })
        assert resp.status_code == 423
        assert resp.json()["detail"]["code"] == "locked_out"


class TestRegenerateRecoveryCode:
    """Copre la rigenerazione del codice di recovery a richiesta dall'Utility,
    disponibile in qualunque momento da autenticati (non solo al primo setup
    o alla migrazione automatica di un vault legacy)."""

    def test_regenerate_requires_authentication(self, tmp_path):
        client = make_client(tmp_path)
        resp = client.post("/api/utility/recovery-code", json={"current_password": MASTER_PASSWORD})
        assert resp.status_code == 401

    def test_regenerate_returns_new_code_different_from_first(self, tmp_path):
        client = make_client(tmp_path)
        resp = client.post("/api/auth/setup", json={
            "new_password": MASTER_PASSWORD, "confirm_password": MASTER_PASSWORD,
        })
        first_code = resp.json()["recovery_code"]

        resp = client.post("/api/utility/recovery-code", json={"current_password": MASTER_PASSWORD})
        assert resp.status_code == 200
        new_code = resp.json()["recovery_code"]
        assert new_code
        assert new_code != first_code

        # Il vecchio codice non è più valido, il nuovo sì.
        resp = client.post("/api/auth/recover/verify", json={"recovery_code": first_code})
        assert resp.status_code == 400
        resp = client.post("/api/auth/recover/verify", json={"recovery_code": new_code})
        assert resp.status_code == 200

    def test_regenerate_wrong_current_password_fails(self, tmp_path):
        client = make_client(tmp_path)
        setup_and_login(client)
        resp = client.post("/api/utility/recovery-code", json={"current_password": "WrongPassword"})
        assert resp.status_code == 400

    def test_regenerate_does_not_affect_credential_data(self, tmp_path):
        client = make_client(tmp_path)
        setup_and_login(client)
        client.post("/api/credentials", json={
            "service": "GitHub", "username": "octocat@example.com", "password": "hunter2-Strong!",
        })

        resp = client.post("/api/utility/recovery-code", json={"current_password": MASTER_PASSWORD})
        assert resp.status_code == 200

        secret = client.get("/api/credentials/GitHub/secret")
        assert secret.status_code == 200
        assert secret.json()["password"] == "hunter2-Strong!"


class TestPasswordHelpers:
    def test_password_strength_endpoint_is_public(self, tmp_path):
        client = make_client(tmp_path)
        resp = client.post("/api/password-strength", json={"password": "Tr0ub4dor&3-correct-horse-battery"})
        assert resp.status_code == 200
        assert resp.json()["score"] >= 3

    def test_password_generator_requires_session(self, tmp_path):
        client = make_client(tmp_path)
        resp = client.post("/api/password-generator", json={"length": 20})
        assert resp.status_code == 401

    def test_password_generator_respects_length(self, tmp_path):
        client = make_client(tmp_path)
        setup_and_login(client)
        resp = client.post("/api/password-generator", json={"length": 24, "exclude_ambiguous": True})
        assert resp.status_code == 200
        assert len(resp.json()["password"]) == 24


class TestCredentialTags:
    def _authed_client(self, tmp_path) -> TestClient:
        client = make_client(tmp_path)
        setup_and_login(client)
        return client

    def test_add_credential_with_tags_exposes_them_in_list_and_secret(self, tmp_path):
        client = self._authed_client(tmp_path)
        client.post("/api/credentials", json={
            "service": "GitHub", "username": "a", "password": "aaaaaaaaaaaa", "tags": ["work", "dev"],
        })

        items = client.get("/api/credentials").json()["items"]
        assert items[0]["tags"] == ["work", "dev"]

        secret = client.get("/api/credentials/GitHub/secret").json()
        assert secret["tags"] == ["work", "dev"]

    def test_update_credential_replaces_tags(self, tmp_path):
        client = self._authed_client(tmp_path)
        client.post("/api/credentials", json={
            "service": "GitHub", "username": "a", "password": "aaaaaaaaaaaa", "tags": ["work"],
        })
        client.put("/api/credentials/GitHub", json={"username": "a", "password": "bbbbbbbbbbbb", "tags": ["personal"]})

        secret = client.get("/api/credentials/GitHub/secret").json()
        assert secret["tags"] == ["personal"]

    def test_filter_credentials_by_tag(self, tmp_path):
        client = self._authed_client(tmp_path)
        client.post("/api/credentials", json={
            "service": "GitHub", "username": "a", "password": "aaaaaaaaaaaa", "tags": ["work"],
        })
        client.post("/api/credentials", json={
            "service": "Netflix", "username": "b", "password": "bbbbbbbbbbbb", "tags": ["personal"],
        })

        resp = client.get("/api/credentials", params={"tag": "work"})
        items = resp.json()["items"]
        assert len(items) == 1
        assert items[0]["service"] == "GitHub"

    def test_list_tags_returns_distinct_tags_across_item_types(self, tmp_path):
        client = self._authed_client(tmp_path)
        client.post("/api/credentials", json={
            "service": "GitHub", "username": "a", "password": "aaaaaaaaaaaa", "tags": ["work"],
        })
        client.post("/api/notes", json={"title": "Nota", "content": "segreto", "tags": ["personal"]})
        client.post("/api/cards", json={"name": "Visa", "card_number": "4111111111111111", "tags": ["work"]})

        resp = client.get("/api/tags")
        assert resp.status_code == 200
        assert resp.json()["tags"] == ["personal", "work"]

    def test_list_tags_requires_authentication(self, tmp_path):
        client = make_client(tmp_path)
        resp = client.get("/api/tags")
        assert resp.status_code == 401


class TestSecureNotesCrud:
    def _authed_client(self, tmp_path) -> TestClient:
        client = make_client(tmp_path)
        setup_and_login(client)
        return client

    def test_add_list_and_get_secret(self, tmp_path):
        client = self._authed_client(tmp_path)
        resp = client.post("/api/notes", json={"title": "Wifi Casa", "content": "SSID: home", "tags": ["casa"]})
        assert resp.status_code == 201

        resp = client.get("/api/notes")
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert len(items) == 1
        assert items[0]["key"] == "Wifi Casa"
        assert items[0]["tags"] == ["casa"]
        assert "content" not in items[0]

        secret = client.get("/api/notes/Wifi Casa/secret")
        assert secret.status_code == 200
        assert secret.json()["content"] == "SSID: home"

    def test_notes_are_not_listed_among_credentials(self, tmp_path):
        client = self._authed_client(tmp_path)
        client.post("/api/notes", json={"title": "Nota", "content": "segreto"})
        client.post("/api/credentials", json={"service": "GitHub", "username": "a", "password": "aaaaaaaaaaaa"})

        items = client.get("/api/credentials").json()["items"]
        assert len(items) == 1
        assert items[0]["service"] == "GitHub"

    def test_add_note_requires_title_and_content(self, tmp_path):
        client = self._authed_client(tmp_path)
        resp = client.post("/api/notes", json={"title": "", "content": "x"})
        assert resp.status_code == 400
        resp = client.post("/api/notes", json={"title": "Nota", "content": ""})
        assert resp.status_code == 400

    def test_add_duplicate_note_title_fails(self, tmp_path):
        client = self._authed_client(tmp_path)
        client.post("/api/notes", json={"title": "Nota", "content": "primo"})
        resp = client.post("/api/notes", json={"title": "Nota", "content": "secondo"})
        assert resp.status_code == 409

    def test_note_name_cannot_collide_with_existing_credential(self, tmp_path):
        client = self._authed_client(tmp_path)
        client.post("/api/credentials", json={"service": "GitHub", "username": "a", "password": "aaaaaaaaaaaa"})
        resp = client.post("/api/notes", json={"title": "GitHub", "content": "x"})
        assert resp.status_code == 409

    def test_update_note(self, tmp_path):
        client = self._authed_client(tmp_path)
        client.post("/api/notes", json={"title": "Nota", "content": "vecchio"})
        resp = client.put("/api/notes/Nota", json={"content": "nuovo", "tags": ["aggiornata"]})
        assert resp.status_code == 200

        secret = client.get("/api/notes/Nota/secret").json()
        assert secret["content"] == "nuovo"
        assert secret["tags"] == ["aggiornata"]

    def test_update_nonexistent_note_fails(self, tmp_path):
        client = self._authed_client(tmp_path)
        resp = client.put("/api/notes/DoesNotExist", json={"content": "x"})
        assert resp.status_code == 404

    def test_delete_note_reuses_generic_credentials_delete_endpoint(self, tmp_path):
        client = self._authed_client(tmp_path)
        client.post("/api/notes", json={"title": "Nota", "content": "x"})
        resp = client.delete("/api/credentials/Nota")
        assert resp.status_code == 200
        assert client.get("/api/notes").json()["items"] == []

    def test_search_filters_notes_by_title(self, tmp_path):
        client = self._authed_client(tmp_path)
        client.post("/api/notes", json={"title": "Wifi Casa", "content": "x"})
        client.post("/api/notes", json={"title": "Codici Backup", "content": "y"})
        resp = client.get("/api/notes", params={"search": "wifi"})
        items = resp.json()["items"]
        assert len(items) == 1
        assert items[0]["key"] == "Wifi Casa"

    def test_notes_require_authentication(self, tmp_path):
        client = make_client(tmp_path)
        assert client.get("/api/notes").status_code == 401
        assert client.post("/api/notes", json={"title": "x", "content": "y"}).status_code == 401


class TestPaymentCardsCrud:
    def _authed_client(self, tmp_path) -> TestClient:
        client = make_client(tmp_path)
        setup_and_login(client)
        return client

    def test_add_list_and_get_secret(self, tmp_path):
        client = self._authed_client(tmp_path)
        resp = client.post("/api/cards", json={
            "name": "Carta Visa", "cardholder": "Mario Rossi", "card_number": "4111111111111111",
            "expiry": "12/29", "cvv": "123", "tags": ["personale"],
        })
        assert resp.status_code == 201

        items = client.get("/api/cards").json()["items"]
        assert len(items) == 1
        assert items[0]["key"] == "Carta Visa"
        assert items[0]["card_number_last4"] == "1111"
        assert items[0]["tags"] == ["personale"]
        assert "card_number" not in items[0]

        secret = client.get("/api/cards/Carta Visa/secret")
        assert secret.status_code == 200
        body = secret.json()
        assert body["card_number"] == "4111111111111111"
        assert body["cardholder"] == "Mario Rossi"
        assert body["cvv"] == "123"

    def test_add_card_requires_name_and_number(self, tmp_path):
        client = self._authed_client(tmp_path)
        resp = client.post("/api/cards", json={"name": "", "card_number": "4111111111111111"})
        assert resp.status_code == 400
        resp = client.post("/api/cards", json={"name": "Carta", "card_number": ""})
        assert resp.status_code == 400

    def test_add_card_optional_fields_can_be_omitted(self, tmp_path):
        client = self._authed_client(tmp_path)
        resp = client.post("/api/cards", json={"name": "Carta Solo Numero", "card_number": "4111111111111111"})
        assert resp.status_code == 201
        secret = client.get("/api/cards/Carta Solo Numero/secret").json()
        assert secret["card_number"] == "4111111111111111"
        assert secret["cardholder"] == ""

    def test_add_duplicate_card_name_fails(self, tmp_path):
        client = self._authed_client(tmp_path)
        client.post("/api/cards", json={"name": "Carta", "card_number": "4111111111111111"})
        resp = client.post("/api/cards", json={"name": "Carta", "card_number": "5555555555554444"})
        assert resp.status_code == 409

    def test_update_card(self, tmp_path):
        client = self._authed_client(tmp_path)
        client.post("/api/cards", json={"name": "Carta", "card_number": "4111111111111111"})
        resp = client.put("/api/cards/Carta", json={
            "cardholder": "Luigi Verdi", "card_number": "5555555555554444", "expiry": "01/30", "cvv": "999",
        })
        assert resp.status_code == 200

        secret = client.get("/api/cards/Carta/secret").json()
        assert secret["card_number"] == "5555555555554444"
        assert secret["cardholder"] == "Luigi Verdi"

    def test_update_nonexistent_card_fails(self, tmp_path):
        client = self._authed_client(tmp_path)
        resp = client.put("/api/cards/DoesNotExist", json={"card_number": "4111111111111111"})
        assert resp.status_code == 404

    def test_delete_card_reuses_generic_credentials_delete_endpoint(self, tmp_path):
        client = self._authed_client(tmp_path)
        client.post("/api/cards", json={"name": "Carta", "card_number": "4111111111111111"})
        resp = client.delete("/api/credentials/Carta")
        assert resp.status_code == 200
        assert client.get("/api/cards").json()["items"] == []

    def test_filter_cards_by_tag(self, tmp_path):
        client = self._authed_client(tmp_path)
        client.post("/api/cards", json={"name": "Visa", "card_number": "4111111111111111", "tags": ["lavoro"]})
        client.post("/api/cards", json={"name": "Mastercard", "card_number": "5555555555554444", "tags": ["personale"]})
        resp = client.get("/api/cards", params={"tag": "lavoro"})
        items = resp.json()["items"]
        assert len(items) == 1
        assert items[0]["key"] == "Visa"

    def test_cards_require_authentication(self, tmp_path):
        client = make_client(tmp_path)
        assert client.get("/api/cards").status_code == 401
        assert client.post("/api/cards", json={"name": "x", "card_number": "4111111111111111"}).status_code == 401


class TestBackupIncludesAllItemTypes:
    def _authed_client(self, tmp_path) -> TestClient:
        client = make_client(tmp_path)
        setup_and_login(client)
        return client

    def test_export_and_reimport_roundtrips_all_item_types(self, tmp_path):
        client = self._authed_client(tmp_path)
        client.post("/api/credentials", json={
            "service": "GitHub", "username": "a", "password": "aaaaaaaaaaaa", "tags": ["work"],
        })
        client.post("/api/notes", json={"title": "Nota", "content": "segreto", "tags": ["personale"]})
        client.post("/api/cards", json={
            "name": "Carta", "cardholder": "Mario Rossi", "card_number": "4111111111111111",
            "expiry": "12/29", "cvv": "123", "tags": ["lavoro"],
        })

        exported = client.get("/api/utility/export").json()
        assert len(exported) == 3

        resp = client.post("/api/utility/import", json={"data": exported, "confirm": True})
        assert resp.status_code == 200
        assert resp.json()["imported_entries"] == 3

        assert client.get("/api/credentials/GitHub/secret").json()["password"] == "aaaaaaaaaaaa"
        assert client.get("/api/notes/Nota/secret").json()["content"] == "segreto"
        assert client.get("/api/cards/Carta/secret").json()["card_number"] == "4111111111111111"
