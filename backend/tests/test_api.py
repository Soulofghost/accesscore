import pytest
from fastapi.testclient import TestClient
import backend.app.database as db_mod
import backend.app.config as cfg_mod
from backend.app.main import app

@pytest.fixture(scope="module")
def client(tmp_path_factory):
    test_db_dir = tmp_path_factory.mktemp("db")
    test_db = str(test_db_dir / "test_accesscore.db")

    cfg_mod.DB_PATH = test_db
    db_mod.DB_PATH = test_db

    holding_conn = db_mod.init_db(test_db)

    with TestClient(app) as c:
        yield c

    holding_conn.close()

def test_healthcheck(client):
    res = client.get("/api/health")
    assert res.status_code == 200
    assert res.json()["service"] == "AccessCore"

def test_user_registration_and_login_lifecycle(client):
    # 1. Register new user
    reg_res = client.post("/api/auth/register", json={
        "email": "sarah.connor@cyberdyne.corp",
        "full_name": "Sarah Connor",
        "password": "ResistanceLeader2026!"
    })
    assert reg_res.status_code == 201
    data = reg_res.json()
    user_id = data["user_id"]
    assert data["assigned_roles"] == ["MEMBER"]

    # 2. Duplicate registration rejection
    dup_res = client.post("/api/auth/register", json={
        "email": "sarah.connor@cyberdyne.corp",
        "full_name": "Duplicate Attempt",
        "password": "Password12345!"
    })
    assert dup_res.status_code == 400

    # 3. Failed login attempt
    fail_res = client.post("/api/auth/login", json={
        "email": "sarah.connor@cyberdyne.corp",
        "password": "IncorrectPassword!"
    })
    assert fail_res.status_code == 401

    # 4. Successful login
    login_res = client.post("/api/auth/login", json={
        "email": "sarah.connor@cyberdyne.corp",
        "password": "ResistanceLeader2026!"
    })
    assert login_res.status_code == 200
    auth_data = login_res.json()
    token = auth_data["access_token"]
    assert "MEMBER" in auth_data["roles"]

    # 5. Verify Token
    verify_res = client.post("/api/auth/verify-token", json={"token": token})
    assert verify_res.status_code == 200
    assert verify_res.json()["valid"] is True
    assert verify_res.json()["user_id"] == user_id

    # 6. Assign elevated roles
    role_res = client.post(f"/api/users/{user_id}/roles", json={
        "role_names": ["OPERATOR", "SECURITY_AUDITOR"]
    })
    assert role_res.status_code == 200
    assert "OPERATOR" in role_res.json()["assigned_roles"]

    # 7. Logout / Token revocation
    logout_res = client.post("/api/auth/logout", json={"token": token})
    assert logout_res.status_code == 200

    # 8. Verifying revoked token now fails
    revoked_verify = client.post("/api/auth/verify-token", json={"token": token})
    assert revoked_verify.status_code == 401
    assert "revoked" in revoked_verify.json()["detail"]

def test_directory_and_audit_logs(client):
    users_res = client.get("/api/users")
    assert users_res.status_code == 200
    assert len(users_res.json()["users"]) >= 2

    roles_res = client.get("/api/roles")
    assert roles_res.status_code == 200
    assert len(roles_res.json()["roles"]) >= 5

    audit_res = client.get("/api/audit-logs")
    assert audit_res.status_code == 200
    assert len(audit_res.json()["logs"]) >= 3
