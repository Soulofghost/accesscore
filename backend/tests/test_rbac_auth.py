import pytest
import datetime
from backend.app.engine.rbac_auth import (
    hash_password,
    verify_password,
    create_access_token,
    decode_access_token,
    check_permission,
    evaluate_lockout
)

SECRET = "test-secret-key-12345"

def test_password_hashing():
    pwd = "UltraSecurePassword2026!"
    h1, s1 = hash_password(pwd)
    h2, s2 = hash_password(pwd, s1)

    assert h1 == h2
    assert verify_password(pwd, s1, h1) is True
    assert verify_password("WrongPassword!", s1, h1) is False

def test_token_creation_and_validation():
    user_id = "user-101"
    email = "test@domain.com"
    roles = ["ADMIN"]

    token = create_access_token(user_id, email, roles, SECRET, expires_in_hours=1)
    assert token is not None

    valid, claims, err = decode_access_token(token, SECRET)
    assert valid is True
    assert claims["sub"] == user_id
    assert claims["email"] == email
    assert claims["roles"] == ["ADMIN"]

def test_token_tampering_and_invalid_signature():
    token = create_access_token("u1", "u1@test.com", ["MEMBER"], SECRET)
    parts = token.split('.')
    # Tamper with payload
    tampered = f"{parts[0]}.eyJyYW5kb20iOiAidmFsIn0.{parts[2]}"
    valid, _, err = decode_access_token(tampered, SECRET)
    assert valid is False
    assert "Invalid cryptographic token signature" in err

def test_rbac_permission_evaluation():
    # Super admin has wildcard
    assert check_permission(["SUPER_ADMIN"], "system:configure") is True
    assert check_permission(["SUPER_ADMIN"], "users:delete") is True

    # Admin has users:write, but not system:configure
    assert check_permission(["ADMIN"], "users:write") is True
    assert check_permission(["ADMIN"], "system:configure") is False

    # Member only has resources:read
    assert check_permission(["MEMBER"], "resources:read") is True
    assert check_permission(["MEMBER"], "users:write") is False

def test_lockout_evaluation():
    # Under limit
    locked, _ = evaluate_lockout(failed_attempts=3, locked_until_iso=None)
    assert locked is False

    # Exceeded limit
    locked, msg = evaluate_lockout(failed_attempts=5, locked_until_iso=None)
    assert locked is True
    assert "exceeded maximum failed" in msg

    # Timed lockout active
    future_time = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=10)).isoformat()
    locked_future, _ = evaluate_lockout(failed_attempts=5, locked_until_iso=future_time)
    assert locked_future is True
