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
