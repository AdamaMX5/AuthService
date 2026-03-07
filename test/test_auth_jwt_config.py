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
