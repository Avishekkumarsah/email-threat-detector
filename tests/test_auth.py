import uuid
import pytest


def test_health_check(client):
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert data["database"] == "connected"
    assert data["model"]["status"] == "loaded"


def test_user_registration_and_login(client):
    unique = uuid.uuid4().hex[:8]
    email = f"test_{unique}@example.com"
    username = f"user_{unique}"
    password = "Password123!"

    # 1. Register
    reg_res = client.post("/api/auth/register", json={
        "name": f"Test User {unique}",
        "username": username,
        "email": email,
        "password": password,
        "confirm_password": password,
    })
    assert reg_res.status_code == 201
    tokens = reg_res.json()
    assert "access_token" in tokens
    assert "refresh_token" in tokens

    # 2. Duplicate registration should be rejected
    dup_res = client.post("/api/auth/register", json={
        "name": f"Test User {unique}",
        "username": username,
        "email": email,
        "password": password,
        "confirm_password": password,
    })
    assert dup_res.status_code == 409

    # 3. Login with email
    login_res = client.post("/api/auth/login", json={
        "username_or_email": email,
        "password": password,
    })
    assert login_res.status_code == 200
    login_tokens = login_res.json()
    access_token = login_tokens["access_token"]
    refresh_token = login_tokens["refresh_token"]

    # 4. Get current user profile
    headers = {"Authorization": f"Bearer {access_token}"}
    me_res = client.get("/api/auth/me", headers=headers)
    assert me_res.status_code == 200
    me = me_res.json()
    assert me["email"] == email
    assert me["username"] == username
    assert me["role"] == "user"

    # 5. Refresh token
    refresh_res = client.post("/api/auth/refresh", json={
        "refresh_token": refresh_token,
    })
    assert refresh_res.status_code == 200
    new_tokens = refresh_res.json()
    assert "access_token" in new_tokens


def test_invalid_login(client):
    res = client.post("/api/auth/login", json={
        "username_or_email": "nonexistent_user_99999@test.com",
        "password": "WrongPassword123",
    })
    assert res.status_code == 401
