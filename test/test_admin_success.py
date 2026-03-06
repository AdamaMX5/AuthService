from pathlib import Path
import json
import pytest
from fastapi import status

from auth import create_access_token
from test_utils import assert_status_code, get_auth_headers, make_user


@pytest.mark.asyncio
async def test_set_roles_success(test_client, test_db):
    admin = make_user(id="admin_1", email="admin1@example.com", roles=["ADMIN", "USER"])
    target = make_user(id="user_1", email="user1@example.com", roles=["USER"])
    test_db.add(admin)
    test_db.add(target)
    await test_db.commit()

    token = create_access_token({"sub": admin.email})
    response = await test_client.post(
        "/admin/set_roles",
        json={"user_id": target.id, "roles": ["USER", "SUPPORT"]},
        headers=get_auth_headers(token),
    )

    assert_status_code(response, status.HTTP_200_OK)
    data = response.json()
    assert data["status"] == "roles_set"
    assert data["roles"] == ["USER", "SUPPORT"]


@pytest.mark.asyncio
async def test_set_permissions_success(test_client, test_db):
    admin = make_user(id="admin_2", email="admin2@example.com", roles=["ADMIN"])
    target = make_user(id="user_2", email="user2@example.com", roles=["USER"])
    test_db.add(admin)
    test_db.add(target)
    await test_db.commit()

    token = create_access_token({"sub": admin.email})
    payload = {
        "user_id": target.id,
        "permissions": {"billing": {"read": True, "write": False}, "feature_x": True},
    }
    response = await test_client.post(
        "/admin/set_permissions",
        json=payload,
        headers=get_auth_headers(token),
    )

    assert_status_code(response, status.HTTP_200_OK)
    data = response.json()
    assert data["status"] == "permissions_set"
    assert data["permissions"]["billing"]["read"] is True
    assert data["permissions"]["feature_x"] is True


@pytest.mark.asyncio
async def test_upsert_permission_success(test_client, test_db):
    admin = make_user(id="admin_3", email="admin3@example.com", roles=["ADMIN"])
    target = make_user(
        id="user_3",
        email="user3@example.com",
        roles=["USER"],
    )
    target.permissions = {"reports": {"read": True}}
    test_db.add(admin)
    test_db.add(target)
    await test_db.commit()

    token = create_access_token({"sub": admin.email})
    response = await test_client.post(
        "/admin/upsert_permission",
        json={"user_id": target.id, "key": "reports", "value": {"read": True, "write": True}},
        headers=get_auth_headers(token),
    )

    assert_status_code(response, status.HTTP_200_OK)
    data = response.json()
    assert data["status"] == "permission_upserted"
    assert data["permissions"]["reports"]["write"] is True


@pytest.mark.asyncio
async def test_remove_permission_success(test_client, test_db):
    admin = make_user(id="admin_4", email="admin4@example.com", roles=["ADMIN"])
    target = make_user(id="user_4", email="user4@example.com", roles=["USER"])
    target.permissions = {"audit": True, "reports": {"read": True}}
    test_db.add(admin)
    test_db.add(target)
    await test_db.commit()

    token = create_access_token({"sub": admin.email})
    response = await test_client.post(
        "/admin/remove_permission",
        json={"user_id": target.id, "key": "audit"},
        headers=get_auth_headers(token),
    )

    assert_status_code(response, status.HTTP_200_OK)
    data = response.json()
    assert data["status"] == "permission_removed"
    assert data["key"] == "audit"
    assert "audit" not in data["permissions"]


@pytest.mark.asyncio
async def test_list_users_success(test_client, test_db):
    admin = make_user(id="admin_5", email="admin5@example.com", roles=["ADMIN"])
    user_a = make_user(id="user_5a", email="user5a@example.com", roles=["USER"])
    user_b = make_user(id="user_5b", email="user5b@example.com", roles=["USER", "SUPPORT"])
    test_db.add(admin)
    test_db.add(user_a)
    test_db.add(user_b)
    await test_db.commit()

    token = create_access_token({"sub": admin.email})
    response = await test_client.get("/admin/users", headers=get_auth_headers(token))

    assert_status_code(response, status.HTTP_200_OK)
    data = response.json()
    assert data["status"] == "users_listed"
    ids = {entry["id"] for entry in data["users"]}
    assert {"admin_5", "user_5a", "user_5b"}.issubset(ids)


@pytest.mark.asyncio
async def test_get_user_success(test_client, test_db):
    admin = make_user(id="admin_6", email="admin6@example.com", roles=["ADMIN"])
    target = make_user(id="user_6", email="user6@example.com", roles=["USER"])
    test_db.add(admin)
    test_db.add(target)
    await test_db.commit()

    token = create_access_token({"sub": admin.email})
    response = await test_client.get(f"/admin/users/{target.id}", headers=get_auth_headers(token))

    assert_status_code(response, status.HTTP_200_OK)
    data = response.json()
    assert data["status"] == "user_loaded"
    assert data["user"]["id"] == target.id
    assert data["user"]["email"] == target.email


@pytest.mark.asyncio
async def test_patch_user_partial_update_success(test_client, test_db):
    admin = make_user(id="admin_7", email="admin7@example.com", roles=["ADMIN"])
    target = make_user(id="user_7", email="user7@example.com", roles=["USER"])
    test_db.add(admin)
    test_db.add(target)
    await test_db.commit()

    token = create_access_token({"sub": admin.email})
    response = await test_client.patch(
        f"/admin/users/{target.id}",
        json={
            "roles": ["USER", "SUPPORT"],
            "permissions": {"reports": {"read": True}},
            "comment": "updated by admin",
        },
        headers=get_auth_headers(token),
    )

    assert_status_code(response, status.HTTP_200_OK)
    data = response.json()
    assert data["status"] == "user_updated"
    assert set(data["updated_fields"]) == {"roles", "permissions", "comment"}
    assert data["user"]["roles"] == ["USER", "SUPPORT"]
    assert data["user"]["permissions"]["reports"]["read"] is True
    assert data["user"]["comment"] == "updated by admin"


async def test_set_jwt_keys_and_get_public_key_success(test_client, test_db):
    admin = make_user(id="admin_jwt", email="admin_jwt@example.com", roles=["ADMIN"])
    test_db.add(admin)
    await test_db.commit()

    token = create_access_token({"sub": admin.email})
    private_key = "dummy-private-key"
    public_key = "dummy-public-key"

    set_response = await test_client.post(
        "/admin/jwt/keys",
        json={
            "private_key": private_key,
            "public_key": public_key,
            "algorithm": "RS256",
        },
        headers=get_auth_headers(token),
    )

    assert_status_code(set_response, status.HTTP_200_OK)
    payload = set_response.json()
    assert payload["status"] == "jwt_keys_set"
    assert payload["persisted"] is True

    private_path = Path(payload["storage"]["private_key_path"])
    public_path = Path(payload["storage"]["public_key_path"])
    assert private_path.exists() is True
    assert public_path.exists() is True

    public_response = await test_client.get("/jwt/public-key")
    assert_status_code(public_response, status.HTTP_200_OK)
    assert public_response.json()["status"] == "ok"
    assert public_response.json()["algorithm"] == "RS256"
    assert public_response.json()["public_key"] == public_key


@pytest.mark.asyncio
async def test_jwt_key_storage_info_admin_success(test_client, test_db):
    admin = make_user(id="admin_storage", email="admin_storage@example.com", roles=["ADMIN"])
    test_db.add(admin)
    await test_db.commit()

    token = create_access_token({"sub": admin.email})
    response = await test_client.get("/admin/jwt/key-storage", headers=get_auth_headers(token))

    assert_status_code(response, status.HTTP_200_OK)
    data = response.json()
    assert "private_key_path" in data
    assert "public_key_path" in data
    assert data["private_key_loaded"] is False
    assert data["public_key_loaded"] is False


@pytest.mark.asyncio
async def test_import_users_creates_and_updates_by_id_when_email_matches(test_client, test_db):
    admin = make_user(id="admin_import_1", email="admin.import1@example.com", roles=["ADMIN"])
    existing = make_user(
        id="u_DG9tx0",
        email="christian@flussmark.de",
        roles=["USER"],
        hashed_password="old_hash",
        is_email_verify=False,
        is_password_verify=False,
    )
    test_db.add(admin)
    test_db.add(existing)
    await test_db.commit()

    token = create_access_token({"sub": admin.email})
    import_payload = [
        {
            "id": "u_DG9tx0",
            "email": "christian@flussmark.de",
            "email_verify": True,
            "hashed_password": "new_hash",
            "hash_scheme": "argon2id",
            "password_verify": True,
            "last_login": "2025-09-04T11:38:38",
            "roles": ["STUDENT"],
            "comment": "updated",
            "deleted_at": None,
        },
        {
            "id": "u_QbE3BE",
            "email": "k.ostwald90@gmail.com",
            "email_verify": True,
            "hashed_password": "new_hash_2",
            "hash_scheme": "argon2id",
            "password_verify": True,
            "last_login": "2025-04-11T13:07:01",
            "roles": ["STUDENT", "MODERATOR"],
            "comment": "",
            "deleted_at": None,
        },
    ]

    response = await test_client.post(
        "/admin/users/import",
        files={"file": ("users.json", json.dumps(import_payload), "application/json")},
        headers=get_auth_headers(token),
    )

    assert_status_code(response, status.HTTP_200_OK)
    data = response.json()
    assert data["status"] == "users_imported"
    assert data["created"] == 1
    assert data["updated"] == 1
    assert data["skipped"] == 0

    list_response = await test_client.get("/admin/users", headers=get_auth_headers(token))
    assert_status_code(list_response, status.HTTP_200_OK)
    users_by_id = {u["id"]: u for u in list_response.json()["users"]}
    assert users_by_id["u_DG9tx0"]["hashed_password"] == "new_hash"
    assert users_by_id["u_DG9tx0"]["roles"] == ["STUDENT"]
    assert users_by_id["u_QbE3BE"]["email"] == "k.ostwald90@gmail.com"


@pytest.mark.asyncio
async def test_import_users_skips_when_existing_id_has_different_email(test_client, test_db):
    admin = make_user(id="admin_import_2", email="admin.import2@example.com", roles=["ADMIN"])
    existing = make_user(id="u_conflict", email="original@example.com", roles=["USER"])
    test_db.add(admin)
    test_db.add(existing)
    await test_db.commit()

    token = create_access_token({"sub": admin.email})
    import_payload = [
        {
            "id": "u_conflict",
            "email": "different@example.com",
            "email_verify": True,
            "hashed_password": "new_hash",
            "password_verify": True,
            "last_login": "2025-09-04T11:38:38",
            "roles": ["STUDENT"],
            "comment": "",
            "deleted_at": None,
        }
    ]

    response = await test_client.post(
        "/admin/users/import",
        files={"file": ("users.json", json.dumps(import_payload), "application/json")},
        headers=get_auth_headers(token),
    )

    assert_status_code(response, status.HTTP_200_OK)
    data = response.json()
    assert data["created"] == 0
    assert data["updated"] == 0
    assert data["skipped"] == 1
    assert data["skipped_reasons"][0]["reason"] == "id already exists with a different email"
