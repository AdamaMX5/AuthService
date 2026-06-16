import pytest
from fastapi import status

from auth import create_access_token
from test_utils import assert_status_code, get_auth_headers, make_user


@pytest.mark.asyncio
async def test_set_roles_gitclient_with_admin_rejected(test_client, test_db):
    """GITCLIENT mixed with ADMIN in the new role list must be rejected."""
    admin = make_user(id="admin_gc1", email="admin_gc1@example.com", roles=["ADMIN"])
    target = make_user(id="user_gc1", email="user_gc1@example.com", roles=[])
    await admin.insert()
    await target.insert()

    token = create_access_token({"sub": admin.email})
    response = await test_client.post(
        "/admin/set_roles",
        json={"user_id": target.id, "roles": ["GITCLIENT", "ADMIN"]},
        headers=get_auth_headers(token),
    )

    assert_status_code(response, status.HTTP_400_BAD_REQUEST)
    assert response.json()["detail"] == "GITCLIENT role must be the only role on a dedicated user account"


@pytest.mark.asyncio
async def test_set_roles_gitclient_to_user_with_existing_roles_rejected(test_client, test_db):
    """Assigning GITCLIENT to a user who already holds ADMIN must be rejected."""
    admin = make_user(id="admin_gc2", email="admin_gc2@example.com", roles=["ADMIN"])
    target = make_user(id="user_gc2", email="user_gc2@example.com", roles=["ADMIN"])
    await admin.insert()
    await target.insert()

    token = create_access_token({"sub": admin.email})
    response = await test_client.post(
        "/admin/set_roles",
        json={"user_id": target.id, "roles": ["GITCLIENT"]},
        headers=get_auth_headers(token),
    )

    assert_status_code(response, status.HTTP_400_BAD_REQUEST)
    assert response.json()["detail"] == "Cannot assign GITCLIENT role to a user with existing roles"


@pytest.mark.asyncio
async def test_set_roles_gitclient_user_gets_additional_role_rejected(test_client, test_db):
    """Adding a non-GITCLIENT role to an existing GITCLIENT user must be rejected.

    When new_roles contains GITCLIENT plus extra roles, guard #1 fires first
    ("GITCLIENT role must be the only role on a dedicated user account") because
    that check runs before the per-user guard #3.  The important thing is that
    the request is rejected with 400 and that guard #3 fires when new_roles
    contains ONLY the extra role (no GITCLIENT), which is tested via a separate
    assertion below.
    """
    admin = make_user(id="admin_gc3", email="admin_gc3@example.com", roles=["ADMIN"])
    target = make_user(id="user_gc3", email="user_gc3@example.com", roles=["GITCLIENT"])
    await admin.insert()
    await target.insert()

    token = create_access_token({"sub": admin.email})

    # Case A: new_roles = ["GITCLIENT", "ADMIN"] — guard #1 fires
    response = await test_client.post(
        "/admin/set_roles",
        json={"user_id": target.id, "roles": ["GITCLIENT", "ADMIN"]},
        headers=get_auth_headers(token),
    )
    assert_status_code(response, status.HTTP_400_BAD_REQUEST)
    assert response.json()["detail"] == "GITCLIENT role must be the only role on a dedicated user account"

    # Case B: new_roles = ["ADMIN"] only — guard #3 fires
    response = await test_client.post(
        "/admin/set_roles",
        json={"user_id": target.id, "roles": ["ADMIN"]},
        headers=get_auth_headers(token),
    )
    assert_status_code(response, status.HTTP_400_BAD_REQUEST)
    assert response.json()["detail"] == "Cannot assign additional roles to a GITCLIENT user"


@pytest.mark.asyncio
async def test_set_roles_gitclient_only_on_clean_user_allowed(test_client, test_db):
    """Assigning GITCLIENT as sole role to a user without prior roles must succeed."""
    admin = make_user(id="admin_gc4", email="admin_gc4@example.com", roles=["ADMIN"])
    target = make_user(id="user_gc4", email="user_gc4@example.com", roles=[])
    await admin.insert()
    await target.insert()

    token = create_access_token({"sub": admin.email})
    response = await test_client.post(
        "/admin/set_roles",
        json={"user_id": target.id, "roles": ["GITCLIENT"]},
        headers=get_auth_headers(token),
    )

    assert_status_code(response, status.HTTP_200_OK)
    data = response.json()
    assert data["status"] == "roles_set"
    assert data["roles"] == ["GITCLIENT"]


@pytest.mark.asyncio
async def test_upsert_permission_gitclient_user_rejected(test_client, test_db):
    """upsert_permission on a GITCLIENT user must be rejected."""
    admin = make_user(id="admin_gc5", email="admin_gc5@example.com", roles=["ADMIN"])
    target = make_user(id="user_gc5", email="user_gc5@example.com", roles=["GITCLIENT"])
    await admin.insert()
    await target.insert()

    token = create_access_token({"sub": admin.email})
    response = await test_client.post(
        "/admin/upsert_permission",
        json={"user_id": target.id, "key": "repo_access", "value": True},
        headers=get_auth_headers(token),
    )

    assert_status_code(response, status.HTTP_400_BAD_REQUEST)
    assert response.json()["detail"] == "GITCLIENT users cannot have permissions"


# ---------------------------------------------------------------------------
# Round-2 fixes: patch_user, import_users, set_permissions, RoleList validator
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_patch_user_gitclient_with_admin_roles_rejected(test_client, test_db):
    """PATCH /admin/users/{id} with roles containing GITCLIENT+ADMIN must be rejected."""
    admin = make_user(id="admin_gc10", email="admin_gc10@example.com", roles=["ADMIN"])
    target = make_user(id="user_gc10", email="user_gc10@example.com", roles=[])
    await admin.insert()
    await target.insert()

    token = create_access_token({"sub": admin.email})
    response = await test_client.patch(
        f"/admin/users/{target.id}",
        json={"roles": ["GITCLIENT", "ADMIN"]},
        headers=get_auth_headers(token),
    )

    assert_status_code(response, status.HTTP_400_BAD_REQUEST)
    assert response.json()["detail"] == "GITCLIENT role must be the only role on a dedicated user account"


@pytest.mark.asyncio
async def test_patch_user_gitclient_permission_rejected(test_client, test_db):
    """PATCH /admin/users/{id} setting permissions on a GITCLIENT user must be rejected."""
    admin = make_user(id="admin_gc11", email="admin_gc11@example.com", roles=["ADMIN"])
    target = make_user(id="user_gc11", email="user_gc11@example.com", roles=["GITCLIENT"])
    await admin.insert()
    await target.insert()

    token = create_access_token({"sub": admin.email})
    response = await test_client.patch(
        f"/admin/users/{target.id}",
        json={"permissions": {"repo_access": True}},
        headers=get_auth_headers(token),
    )

    assert_status_code(response, status.HTTP_400_BAD_REQUEST)
    assert response.json()["detail"] == "GITCLIENT users cannot have permissions"


@pytest.mark.asyncio
async def test_import_users_gitclient_mixed_roles_skipped(test_client, test_db):
    """Importing a user with roles [GITCLIENT, ADMIN] must be skipped with a reason."""
    admin = make_user(id="admin_gc12", email="admin_gc12@example.com", roles=["ADMIN"])
    await admin.insert()

    import io, json as _json
    payload = [
        {
            "id": "user_gc12",
            "email": "user_gc12@example.com",
            "hashed_password": "$2b$12$somehash",
            "roles": ["GITCLIENT", "ADMIN"],
        }
    ]
    file_bytes = _json.dumps(payload).encode()

    token = create_access_token({"sub": admin.email})
    response = await test_client.post(
        "/admin/users/import",
        files={"file": ("users.json", io.BytesIO(file_bytes), "application/json")},
        headers=get_auth_headers(token),
    )

    assert_status_code(response, status.HTTP_200_OK)
    data = response.json()
    assert data["created"] == 0
    assert data["skipped"] == 1
    assert any(
        "GITCLIENT" in r.get("reason", "") for r in data["skipped_reasons"]
    ), f"Expected GITCLIENT mention in skipped_reasons, got: {data['skipped_reasons']}"


@pytest.mark.asyncio
async def test_set_permissions_gitclient_user_rejected(test_client, test_db):
    """POST /admin/set_permissions on a GITCLIENT user must be rejected."""
    admin = make_user(id="admin_gc13", email="admin_gc13@example.com", roles=["ADMIN"])
    target = make_user(id="user_gc13", email="user_gc13@example.com", roles=["GITCLIENT"])
    await admin.insert()
    await target.insert()

    token = create_access_token({"sub": admin.email})
    response = await test_client.post(
        "/admin/set_permissions",
        json={"user_id": target.id, "permissions": {"repo_access": True}},
        headers=get_auth_headers(token),
    )

    assert_status_code(response, status.HTTP_400_BAD_REQUEST)
    assert response.json()["detail"] == "GITCLIENT users cannot have permissions"


@pytest.mark.asyncio
async def test_set_roles_case_insensitive(test_client, test_db):
    """RoleList validator normalises lowercase 'gitclient' to 'GITCLIENT' — request must succeed."""
    admin = make_user(id="admin_gc14", email="admin_gc14@example.com", roles=["ADMIN"])
    target = make_user(id="user_gc14", email="user_gc14@example.com", roles=[])
    await admin.insert()
    await target.insert()

    token = create_access_token({"sub": admin.email})
    response = await test_client.post(
        "/admin/set_roles",
        json={"user_id": target.id, "roles": ["gitclient"]},
        headers=get_auth_headers(token),
    )

    assert_status_code(response, status.HTTP_200_OK)
    data = response.json()
    assert data["status"] == "roles_set"
    assert data["roles"] == ["GITCLIENT"]
