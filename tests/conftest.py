import os
import sys
import pytest
from fastapi.testclient import TestClient

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.app.main import app
from backend.app.core.config import get_settings

settings = get_settings()


@pytest.fixture(scope="session")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="session")
def auth_headers(client):
    # Log in as the default admin seeded in lifespan
    res = client.post("/api/auth/login", json={
        "username_or_email": settings.ADMIN_EMAIL or "admin@emailthreat.com",
        "password": settings.ADMIN_PASSWORD or "Admin@1234",
    })
    assert res.status_code == 200, f"Admin login failed: {res.text}"
    token = res.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}
