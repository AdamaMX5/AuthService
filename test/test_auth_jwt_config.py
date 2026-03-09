import auth


def test_rs_keys_are_generated_and_used_when_missing(tmp_path):
    auth.ALGORITHM = "RS256"
    auth.JWT_PRIVATE_KEY = None
    auth.JWT_PUBLIC_KEY = None
    auth.JWT_PRIVATE_KEY_PATH = str(tmp_path / "jwt_private.pem")
    auth.JWT_PUBLIC_KEY_PATH = str(tmp_path / "jwt_public.pem")

    token = auth.create_access_token({"sub": "user@example.com"})

    assert (tmp_path / "jwt_private.pem").exists()
    assert (tmp_path / "jwt_public.pem").exists()

    payload = auth.verify_jwt(token)
    assert payload is not None
    assert payload["sub"] == "user@example.com"


def test_null_like_passphrase_is_treated_as_no_encryption():
    auth.ALGORITHM = "RS256"
    private_key, public_key = auth._generate_rsa_key_pair()
    auth.JWT_PRIVATE_KEY = private_key
    auth.JWT_PUBLIC_KEY = public_key
    auth.JWT_PRIVATE_KEY_PASSPHRASE = auth._normalize_private_key_passphrase("null")

    token = auth.create_access_token({"sub": "null-passphrase@example.com"})
    payload = auth.verify_jwt(token)

    assert payload is not None
    assert payload["sub"] == "null-passphrase@example.com"


def test_build_access_token_payload_contains_email_roles_permissions():
    payload = auth.build_access_token_payload(
        email="claims@example.com",
        roles=["USER", "ADMIN"],
        permissions={"reports": {"read": True}},
    )

    token = auth.create_access_token(payload)
    decoded = auth.verify_jwt(token)

    assert decoded is not None
    assert decoded["sub"] == "claims@example.com"
    assert decoded["email"] == "claims@example.com"
    assert decoded["roles"] == ["USER", "ADMIN"]
    assert decoded["permissions"]["reports"]["read"] is True
