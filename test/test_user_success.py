# test_user_success.py
import pytest
from fastapi import status
from datetime import datetime, timedelta
from unittest.mock import patch, AsyncMock

from models import User, Device, RefreshToken
from auth import get_password_hash, verify_password, hash_token, get_current_user
from main import app
import logging

from test_utils import assert_status_code, make_user

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


class TestUserRouterSuccess:
    """Success-Tests für den User-Router - alle Endpunkte mit korrekten Eingaben"""

    @pytest.mark.asyncio
    async def test_login_new_user_registration_started(self, test_client, test_db):
        """Test: Login mit neuem User startet Registrierungsprozess"""
        # Arrange
        login_data = {
            "email": "newuser@example.com",
            "password": "securePassword123!"
        }

        # Act
        response = await test_client.post("/user/login", json=login_data)

        # Assert
        assert_status_code(response, status.HTTP_200_OK)
        data = response.json()
        assert data["status"] == "register"
        assert data["email"] == "newuser@example.com"
        assert data["access_token"] == ""
        assert data["roles"] == []

        # Verify User wurde in DB erstellt
        user = await User.find_one(User.email == "newuser@example.com")
        assert user is not None
        assert user.is_password_verify is False
        assert user.is_email_verify is False
        assert user.last_login is not None

    @pytest.mark.asyncio
    async def test_login_existing_user_success(self, test_client, test_db):
        """Test: Erfolgreicher Login mit bestehendem verifiziertem User"""
        # Arrange
        user = make_user(
            id="test_user_123",
            email="verified@example.com",
            password="correctPassword123!",
        )
        await user.insert()

        login_data = {
            "email": "verified@example.com",
            "password": "correctPassword123!"
        }

        # Act
        response = await test_client.post("/user/login", json=login_data)

        # Assert
        assert_status_code(response, status.HTTP_200_OK)
        data = response.json()
        assert data["status"] == "login"
        assert data["email"] == "verified@example.com"
        assert data["id"] == "test_user_123"
        assert "access_token" in data
        assert "USER" in data["roles"]

        # Verify last_login is updated
        user = await User.get("test_user_123")
        assert user.last_login > (datetime.utcnow() - timedelta(minutes=1))

    @pytest.mark.asyncio
    async def test_login_with_device_fingerprint(self, test_client, test_db):
        """Test: Login mit Device-Fingerprint speichert Device"""
        # Arrange
        user = make_user(
            id="device_user_123",
            email="device@example.com",
            password="devicePassword123!",
        )
        await user.insert()

        login_data = {
            "email": "device@example.com",
            "password": "devicePassword123!",
            "device_fingerprint": "unique_device_123",
            "device_name": "My Chrome Browser"
        }

        # Act
        response = await test_client.post("/user/login", json=login_data)

        # Assert
        assert_status_code(response, status.HTTP_200_OK)

        # Verify Device wurde gespeichert
        device = await Device.find_one(
            Device.user_id == "device_user_123",
            Device.fingerprint == "unique_device_123",
        )
        assert device is not None
        assert device.name == "My Chrome Browser"
        assert device.trusted is True

    @pytest.mark.asyncio
    async def test_login_user_needs_email_verification(self, test_client, test_db):
        """Test: Login sendet Verifikations-Email wenn nicht verifiziert"""
        # Arrange
        user = make_user(
            id="verify_user_123",
            email="unverified@example.com",
            password="verifyPassword123!",
            is_password_verify=True,
            is_email_verify=False,  # Email nicht verifiziert
        )
        await user.insert()

        login_data = {
            "email": "unverified@example.com",
            "password": "verifyPassword123!"
        }

        # Mock send_verification_email
        with patch("user_router.send_verification_email", autospec=True) as mock_send:
            # Act
            response = await test_client.post("/user/login", json=login_data)

            # Assert
            assert_status_code(response, status.HTTP_200_OK)
            data = response.json()
            assert data["status"] == "login_with_verify_email_send"

            # Verify Email wurde gesendet
            mock_send.assert_called_once()
            user = await User.get("verify_user_123")
            assert user.email_verify_token is not None

    @pytest.mark.asyncio
    async def test_login_existing_device_updated(self, test_client, test_db):
        """Test: Login mit bestehendem Device updated last_use"""
        # Arrange
        user = make_user(
            id="existing_device_user",
            email="existing@example.com",
            password="password123!",
        )
        await user.insert()

        # Vorhandenes Device erstellen
        old_time = datetime.utcnow() - timedelta(days=7)
        device = Device(
            id="existing_device_123",
            user_id="existing_device_user",
            fingerprint="existing_fingerprint",
            last_use=old_time
        )
        await device.insert()

        login_data = {
            "email": "existing@example.com",
            "password": "password123!",
            "device_fingerprint": "existing_fingerprint"
        }

        # Act
        response = await test_client.post("/user/login", json=login_data)

        # Assert
        assert_status_code(response, status.HTTP_200_OK)

        # Verify Device last_use wurde aktualisiert
        device = await Device.get("existing_device_123")
        assert device.last_use > old_time

    @pytest.mark.asyncio
    async def test_register_user_success(self, test_client, test_db):
        """Test: Success User-Registration"""
        # Arrange
        user = make_user(
            id="register_user_123",
            email="register@example.com",
            password="registerPassword123!",
            is_password_verify=False,
            is_email_verify=False,
            roles=[],
        )
        await user.insert()

        register_data = {
            "email": "register@example.com",
            "repassword": "registerPassword123!"
        }

        # Mock send_verification_email
        with patch("user_router.send_verification_email"):
            # Act
            response = await test_client.post("/user/register", json=register_data)

            # Assert
            assert_status_code(response, status.HTTP_201_CREATED)
            data = response.json()
            assert data["id"] == "register_user_123"
            assert data["email"] == "register@example.com"
            assert "access_token" in data
            assert data["access_token"] != ""
            assert data["status"] == "login_with_verify_email_send"

            # Verify User wurde aktualisiert
            user = await User.get("register_user_123")
            assert user.is_password_verify is True
            assert user.email_verify_token is not None
            assert "USER" in user.roles

    @pytest.mark.asyncio
    async def test_register_first_user_becomes_admin(self, test_client, test_db):
        """Test: Erster registrierter User wird Admin"""
        # Arrange - Keine Admins in der DB
        user = make_user(
            id="first_user_123",
            email="first@example.com",
            password="firstPassword123!",
            is_password_verify=False,
            is_email_verify=False,
            roles=[],
        )
        await user.insert()

        register_data = {
            "email": "first@example.com",
            "repassword": "firstPassword123!"
        }

        with patch("user_router.send_verification_email"):
            # Act
            response = await test_client.post("/user/register", json=register_data)

            # Assert
            assert_status_code(response, status.HTTP_201_CREATED)

            # Verify User hat ADMIN und USER Rolle
            user = await User.get("first_user_123")
            assert "ADMIN" in user.roles
            assert "USER" in user.roles

    @pytest.mark.asyncio
    async def test_register_with_existing_admin(self, test_client, test_db):
        """Test: Registrierung wenn schon Admin existiert"""
        # Arrange - Admin existiert bereits
        admin_user = make_user(
            id="existing_admin",
            email="admin@example.com",
            password="adminPassword123!",
            roles=["ADMIN", "USER"],
        )
        await admin_user.insert()

        new_user = make_user(
            id="new_user_456",
            email="newuser@example.com",
            password="newPassword123!",
            is_password_verify=False,
            is_email_verify=False,
            roles=[],
        )
        await new_user.insert()

        register_data = {
            "email": "newuser@example.com",
            "repassword": "newPassword123!"
        }

        logger.warning("Starting test_register_with_existing_admin")
        with patch("user_router.send_verification_email"):
            # Act
            response = await test_client.post("/user/register", json=register_data)

            # Assert
            assert_status_code(response, status.HTTP_201_CREATED)

            # Verify neuer User ist NICHT Admin
            new_user = await User.get("new_user_456")
            assert "ADMIN" not in new_user.roles
            assert "USER" in new_user.roles

    @pytest.mark.asyncio
    async def test_verify_email_success(self, test_client, test_db):
        """Test: Erfolgreiche Email-Verifikation"""
        # Arrange
        user = make_user(
            id="verify_me_123",
            email="verify@example.com",
            password="veryfyEmail123!",
            email_verify_token="valid_token_123",
            is_email_verify=False,
        )
        await user.insert()

        # Act
        response = await test_client.get(
            "/user/verify-email",
            params={"token": "valid_token_123", "user_id": "verify_me_123"}
        )

        # Assert
        assert_status_code(response, status.HTTP_200_OK)
        data = response.json()
        assert data["status"] == "email_verified"

        # Verify User wurde aktualisiert
        user = await User.get("verify_me_123")
        assert user.is_email_verify is True
        assert user.email_verify_token is None

    @pytest.mark.asyncio
    async def test_verify_email_already_verified(self, test_client, test_db):
        # Arrange
        user = make_user(
            id="already_verified",
            email="verified@example.com",
            password="verifyedEmail123!",
            email_verify_token="any_token",
        )
        await user.insert()

        # Act
        response = await test_client.get(
            "/user/verify-email",
            params={"token": "any_token", "user_id": "already_verified"}
        )

        # Assert
        assert_status_code(response, status.HTTP_200_OK)
        data = response.json()
        assert data["status"] == "email_already_verified"

    # ========== PASSWORD RESET SUCCESS TESTS ==========

    @pytest.mark.asyncio
    async def test_password_reset_request_success(self, test_client, test_db):
        """Test: Erfolgreiche Passwort-Reset-Anfrage"""
        # Arrange
        user = make_user(
            id="reset_user_123",
            email="reset@example.com",
            password="toResetPassword123!",
        )
        await user.insert()

        # Mock send_password_reset_email
        with patch("user_router.send_password_reset_email") as mock_send:
            # Act
            response = await test_client.post(
                "/user/password-reset-request",
                params={"email": "reset@example.com"}
            )

            # Assert
            assert_status_code(response, status.HTTP_200_OK)
            mock_send.assert_called_once()

            # Verify Token wurde gesetzt
            user = await User.get("reset_user_123")
            assert user.password_reset_token is not None

    @pytest.mark.asyncio
    async def test_reset_password_success(self, test_client, test_db):
        """Test: Erfolgreiche Passwort-Änderung"""
        # Arrange
        user = make_user(
            id="changepw_user_123",
            email="changepw@example.com",
            password_reset_token="valid_reset_token",
            hashed_password="old_hashed_password",
        )
        await user.insert()

        old_password_hash = user.hashed_password

        # Act
        response = await test_client.post(
            "/user/reset-password",
            params={
                "token": "valid_reset_token",
                "user_id": "changepw_user_123",
                "new_password": "NewSecurePassword123!",
                "repassword": "NewSecurePassword123!"
            }
        )

        # Assert
        assert_status_code(response, status.HTTP_200_OK)
        data = response.json()
        assert data["status"] == "password_reset"

        # Verify Passwort wurde geändert
        user = await User.get("changepw_user_123")
        assert user.hashed_password != old_password_hash
        assert user.password_reset_token is None

    @pytest.mark.asyncio
    async def test_refresh_token_success(self, test_client, test_db):
        """Test: Erfolgreiches Token-Refresh"""
        # Arrange - User erstellen
        user = make_user(
            id="refresh_user_123",
            email="refresh@example.com",
            password="password123!",
        )
        await user.insert()

        # Device erstellen
        device = Device(
            id="refresh_device_123",
            user_id="refresh_user_123",
            fingerprint="refresh_fingerprint",
            last_use=datetime.utcnow() - timedelta(days=1)
        )
        await device.insert()

        # Refresh Token erstellen (noch nicht abgelaufen)
        refresh_token = RefreshToken(
            id="refresh_token_123",
            device_id="refresh_device_123",
            token_hash=hash_token("valid_refresh_token"),
            issued_at=datetime.utcnow() - timedelta(days=1),
            expires_at=datetime.utcnow() + timedelta(days=6),
            revoked=False
        )
        await refresh_token.insert()

        # Mock hash_token um korrekten Hash zurückzugeben
        with patch("user_router.create_token", return_value="new_refresh_token"):
            with patch("user_router.create_access_token", return_value="new_access_token"):
                # Act
                response = await test_client.post(
                    "/user/refresh",
                    cookies={"refresh_token": "valid_refresh_token"}
                )
                # Assert
                assert_status_code(response, status.HTTP_200_OK)
                data = response.json()
                assert data["access_token"] == "new_access_token"

                # Verify Token Rotation
                old_token = await RefreshToken.get("refresh_token_123")
                assert old_token.revoked is True

                # Neuer Token sollte existieren
                new_token = await RefreshToken.find_one(
                    RefreshToken.device_id == "refresh_device_123",
                    RefreshToken.revoked == False,
                )
                assert new_token is not None

    @pytest.mark.asyncio
    async def test_logout_success_with_token(self, test_client, test_db):
        # Arrange
        device = Device(
            id="logout_device_123",
            user_id="logout_user_123",
            fingerprint="logout_fingerprint",
            last_use=datetime.utcnow() - timedelta(days=1)
        )
        await device.insert()

        refresh_token = RefreshToken(
            id="logout_token_123",
            device_id="logout_device_123",
            token_hash="logout_token_hash",
            expires_at=datetime.utcnow() + timedelta(days=7),
            revoked=False
        )
        await refresh_token.insert()

        with patch("user_router.hash_token", return_value="logout_token_hash"):
            # Act
            response = await test_client.post(
                "/user/logout",
                cookies={"refresh_token": "valid_logout_token"}
            )

            # Assert
            assert_status_code(response, status.HTTP_200_OK)
            data = response.json()
            assert data["status"] == "logged_out"

            # Verify Token wurde revoked
            token = await RefreshToken.get("logout_token_123")
            assert token.revoked is True

    @pytest.mark.asyncio
    async def test_logout_success_without_token(self, test_client, test_db):
        # Act
        response = await test_client.post("/user/logout")

        # Assert
        assert_status_code(response, status.HTTP_200_OK)
        data = response.json()
        assert data["status"] == "logged_out"

    @pytest.mark.asyncio
    async def test_logout_all_success(self, test_client, test_db):
        # Arrange
        user = make_user(
            id="logout_all_user",
            email="logoutall@example.com",
            password="password123!",
        )
        await user.insert()

        # create two devices for the user
        device1 = Device(id="device1", user_id=user.id, fingerprint="fingerprint1", last_use=datetime.utcnow() - timedelta(days=1))
        device2 = Device(id="device2", user_id=user.id, fingerprint="fingerprint2", last_use=datetime.utcnow() - timedelta(days=1))
        await device1.insert()
        await device2.insert()

        # create two refresh tokens for the devices
        token1 = RefreshToken(id="token1", device_id="device1", token_hash=hash_token("token_1"), expires_at=datetime.utcnow() + timedelta(days=6), revoked=False)
        token2 = RefreshToken(id="token2", device_id="device2", token_hash=hash_token("token_2"), expires_at=datetime.utcnow() + timedelta(days=6), revoked=False)
        await token1.insert()
        await token2.insert()

        def override_get_current_user():
            return user

        # Mock get_current_user
        app.dependency_overrides[get_current_user] = override_get_current_user

        response = await test_client.post("/user/logout-all")

        app.dependency_overrides.clear()

        assert_status_code(response, status.HTTP_200_OK)
        assert response.json()["status"] == "logged_out_all", f"Expected status 'logged_out_all', but got {response.json()['status']}"

        # Verify all tokens are revoked
        t1 = await RefreshToken.get("token1")
        t2 = await RefreshToken.get("token2")
        assert t1.revoked is True, f"Expected token1.revoked == true, but token is {t1}"
        assert t2.revoked is True, f"Expected token2.revoked == true, but token is {t2}"

    @pytest.mark.asyncio
    async def test_login_without_device_info_generates_fingerprint(self, test_client, test_db):
        # Arrange
        user = make_user(
            id="no_device_user",
            email="nodevice@example.com",
            password="password123!",
        )
        await user.insert()

        login_data = {
            "email": "nodevice@example.com",
            "password": "password123!"
            # Keine Device-Informationen
        }

        # Mock create_token für Fingerprint-Generierung
        with patch("user_router.create_token", return_value="generated_fingerprint_123"):
            # Act
            response = await test_client.post("/user/login", json=login_data)

            # Assert
            assert_status_code(response, status.HTTP_200_OK)

            # Verify Device was created with generated fingerprint
            device = await Device.find_one(Device.user_id == "no_device_user")
            assert device is not None, f"Expected a server generated device for user 'no_device_user' but device = none."
            assert device.fingerprint == "generated_fingerprint_123", f"Expected fingerprint 'generated_fingerprint_123' but got {device.fingerprint}"
            assert device.name == "Unknown Device", f"Expected device name 'Unknown Device' but got {device.name}"

    @pytest.mark.asyncio
    async def test_consecutive_two_logins_same_device(self, test_client, test_db):
        # Arrange
        user = make_user(
            id="multi_login_user",
            email="multilogin@example.com",
            password="password123!",
        )
        await user.insert()

        login_data = {
            "email": "multilogin@example.com",
            "password": "password123!",
            "device_fingerprint": "same_fingerprint",
        }

        # first Login
        response = await test_client.post("/user/login", json=login_data)
        assert_status_code(response, status.HTTP_200_OK)

        # Device Count after first login
        device_list = await Device.find(Device.user_id == "multi_login_user").to_list()
        assert len(device_list) == 1, f"Expected 1 device for user 'multi_login_user' after first login, but got {len(device_list)}"

        # second Login with same fingerprint
        response2 = await test_client.post("/user/login", json=login_data)
        assert_status_code(response2, status.HTTP_200_OK)

        # Device Count should still be 1, not 2
        device_list = await Device.find(Device.user_id == "multi_login_user").to_list()
        assert len(device_list) == 1, f"Expected still only 1 device for user 'multi_login_user' after second login but got {len(device_list)}, maybe 2 new random fingerprint was generated instead of using the provided one?"

        device = device_list[0]
        assert device.fingerprint == "same_fingerprint", f"Expected device fingerprint 'same_fingerprint' but got {device.fingerprint}, maybe a random fingerprint was generated instead of using the provided one?"
