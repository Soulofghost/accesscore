import uuid
import datetime
from fastapi import APIRouter, HTTPException, Header, status
from typing import Optional, List

from backend.app.database import get_connection
from backend.app.config import SECRET_KEY, MAX_FAILED_LOGIN_ATTEMPTS, LOCKOUT_DURATION_MINUTES
from backend.app.schemas import (
    RegisterRequest, LoginRequest, TokenVerifyRequest,
    RoleAssignRequest, CreateRoleRequest
)
from backend.app.engine.rbac_auth import (
    hash_password,
    verify_password,
    create_access_token,
    decode_access_token,
    check_permission,
    evaluate_lockout,
    DEFAULT_ROLE_PERMISSIONS
)

router = APIRouter(prefix="/api", tags=["auth"])

def _log_audit_event(user_id: Optional[str], email: str, event_type: str, status_str: str, details: str = ""):
    conn = get_connection()
    cursor = conn.cursor()
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    cursor.execute("""
    INSERT INTO auth_audit_logs (id, user_id, email, event_type, status, details, timestamp)
    VALUES (?, ?, ?, ?, ?, ?, ?);
    """, (str(uuid.uuid4()), user_id, email, event_type, status_str, details, now_iso))
    conn.commit()
    conn.close()

@router.get("/health")
def healthcheck():
    return {"status": "ok", "service": "AccessCore", "version": "1.0.0"}

@router.post("/auth/register", status_code=status.HTTP_201_CREATED)
def register(payload: RegisterRequest):
    conn = get_connection()
    cursor = conn.cursor()

    email_clean = payload.email.strip().lower()
    cursor.execute("SELECT id FROM users WHERE email = ?;", (email_clean,))
    if cursor.fetchone():
        conn.close()
        _log_audit_event(None, email_clean, "USER_REGISTRATION", "FAILED", "Duplicate email registration attempt")
        raise HTTPException(status_code=400, detail="User with this email already exists")

    user_id = str(uuid.uuid4())
    pwd_hash, salt = hash_password(payload.password)
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

    cursor.execute("""
    INSERT INTO users (id, email, full_name, password_hash, salt, is_active, failed_attempts, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, 1, 0, ?, ?);
    """, (user_id, email_clean, payload.full_name.strip(), pwd_hash, salt, now_iso, now_iso))

    # Assign default MEMBER role
    cursor.execute("SELECT id FROM roles WHERE name = 'MEMBER';",)
    role_row = cursor.fetchone()
    if role_row:
        cursor.execute("INSERT INTO user_roles (user_id, role_id) VALUES (?, ?);", (user_id, role_row[0]))

    conn.commit()
    conn.close()

    _log_audit_event(user_id, email_clean, "USER_REGISTRATION", "SUCCESS", "Account registered with role MEMBER")

    return {
        "user_id": user_id,
        "email": email_clean,
        "full_name": payload.full_name.strip(),
        "assigned_roles": ["MEMBER"],
        "created_at": now_iso
    }

@router.post("/auth/login")
def login(payload: LoginRequest):
    conn = get_connection()
    cursor = conn.cursor()

    email_clean = payload.email.strip().lower()
    cursor.execute("SELECT * FROM users WHERE email = ?;", (email_clean,))
    user = cursor.fetchone()

    if not user:
        conn.close()
        _log_audit_event(None, email_clean, "AUTH_LOGIN", "FAILED", "User does not exist")
        raise HTTPException(status_code=401, detail="Invalid email or password")

    user_id = user["id"]

    # Check lockout
    is_locked, lock_msg = evaluate_lockout(user["failed_attempts"], user["locked_until"], MAX_FAILED_LOGIN_ATTEMPTS)
    if is_locked:
        conn.close()
        _log_audit_event(user_id, email_clean, "AUTH_LOGIN", "BLOCKED", lock_msg)
        raise HTTPException(status_code=423, detail=lock_msg)

    # Verify password
    if not verify_password(payload.password, user["salt"], user["password_hash"]):
        failed_count = user["failed_attempts"] + 1
        now_dt = datetime.datetime.now(datetime.timezone.utc)
        locked_until = None

        if failed_count >= MAX_FAILED_LOGIN_ATTEMPTS:
            locked_dt = now_dt + datetime.timedelta(minutes=LOCKOUT_DURATION_MINUTES)
            locked_until = locked_dt.isoformat()

        cursor.execute("""
        UPDATE users SET failed_attempts = ?, locked_until = ?, updated_at = ? WHERE id = ?;
        """, (failed_count, locked_until, now_dt.isoformat(), user_id))
        conn.commit()
        conn.close()

        detail_msg = f"Invalid email or password. Attempt {failed_count}/{MAX_FAILED_LOGIN_ATTEMPTS}."
        if locked_until:
            detail_msg = f"Account locked for {LOCKOUT_DURATION_MINUTES} minutes due to excessive failed attempts."

        _log_audit_event(user_id, email_clean, "AUTH_LOGIN", "FAILED", detail_msg)
        raise HTTPException(status_code=401, detail=detail_msg)

    # Successful login: reset failed attempts
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    cursor.execute("""
    UPDATE users SET failed_attempts = 0, locked_until = NULL, updated_at = ? WHERE id = ?;
    """, (now_iso, user_id))

    # Fetch user roles
    cursor.execute("""
    SELECT r.name FROM roles r
    JOIN user_roles ur ON r.id = ur.role_id
    WHERE ur.user_id = ?;
    """, (user_id,))
    roles = [r[0] for r in cursor.fetchall()] or ["MEMBER"]

    conn.commit()
    conn.close()

    token = create_access_token(user_id, email_clean, roles, SECRET_KEY)
    _log_audit_event(user_id, email_clean, "AUTH_LOGIN", "SUCCESS", f"Authenticated with roles: {', '.join(roles)}")

    return {
        "access_token": token,
        "token_type": "Bearer",
        "user_id": user_id,
        "email": email_clean,
        "full_name": user["full_name"],
        "roles": roles
    }

@router.post("/auth/verify-token")
def verify_token(payload: TokenVerifyRequest):
    valid, claims, err_msg = decode_access_token(payload.token, SECRET_KEY)
    if not valid or not claims:
        raise HTTPException(status_code=401, detail=f"Token validation failed: {err_msg}")

    # Check blacklist
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT jti FROM token_blacklist WHERE jti = ?;", (claims["jti"],))
    if cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=401, detail="Token has been revoked")
    conn.close()

    return {
        "valid": True,
        "user_id": claims["sub"],
        "email": claims["email"],
        "roles": claims["roles"],
        "expires_at": claims["exp"]
    }

@router.post("/auth/logout")
def logout(payload: TokenVerifyRequest):
    valid, claims, _ = decode_access_token(payload.token, SECRET_KEY)
    if valid and claims:
        conn = get_connection()
        cursor = conn.cursor()
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        cursor.execute("INSERT OR IGNORE INTO token_blacklist (jti, revoked_at, reason) VALUES (?, ?, 'User logout');",
                       (claims["jti"], now_iso))
        conn.commit()
        conn.close()
        _log_audit_event(claims["sub"], claims["email"], "AUTH_LOGOUT", "SUCCESS", "Session token revoked")

    return {"message": "Session successfully terminated"}

@router.get("/users")
def list_users():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT id, email, full_name, is_active, failed_attempts, locked_until, created_at FROM users ORDER BY created_at ASC;")
    users = cursor.fetchall()

    results = []
    for u in users:
        cursor.execute("""
        SELECT r.name FROM roles r
        JOIN user_roles ur ON r.id = ur.role_id
        WHERE ur.user_id = ?;
        """, (u["id"],))
        roles = [r[0] for r in cursor.fetchall()]

        is_locked, _ = evaluate_lockout(u["failed_attempts"], u["locked_until"])

        results.append({
            "id": u["id"],
            "email": u["email"],
            "full_name": u["full_name"],
            "roles": roles,
            "is_active": bool(u["is_active"]),
            "is_locked": is_locked,
            "failed_attempts": u["failed_attempts"],
            "created_at": u["created_at"]
        })

    conn.close()
    return {"total": len(results), "users": results}

@router.post("/users/{user_id}/roles")
def assign_roles(user_id: str, payload: RoleAssignRequest):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT email FROM users WHERE id = ?;", (user_id,))
    u_row = cursor.fetchone()
    if not u_row:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")

    cursor.execute("DELETE FROM user_roles WHERE user_id = ?;", (user_id,))

    assigned = []
    for role_name in payload.role_names:
        cursor.execute("SELECT id FROM roles WHERE name = ?;", (role_name.upper(),))
        r_row = cursor.fetchone()
        if r_row:
            cursor.execute("INSERT INTO user_roles (user_id, role_id) VALUES (?, ?);", (user_id, r_row[0]))
            assigned.append(role_name.upper())

    conn.commit()
    conn.close()

    _log_audit_event(user_id, u_row[0], "ROLE_ASSIGNMENT", "SUCCESS", f"Assigned roles: {', '.join(assigned)}")

    return {
        "user_id": user_id,
        "assigned_roles": assigned
    }

@router.get("/roles")
def list_roles():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM roles ORDER BY name ASC;")
    rows = cursor.fetchall()
    conn.close()

    results = []
    for r in rows:
        perms = list(DEFAULT_ROLE_PERMISSIONS.get(r["name"], []))
        results.append({
            "id": r["id"],
            "name": r["name"],
            "description": r["description"],
            "is_system": bool(r["is_system"]),
            "permissions": perms
        })

    return {"total": len(results), "roles": results}

@router.get("/audit-logs")
def list_audit_logs(limit: int = 50):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM auth_audit_logs ORDER BY timestamp DESC LIMIT ?;", (limit,))
    rows = cursor.fetchall()
    conn.close()

    results = [{
        "id": r["id"],
        "user_id": r["user_id"],
        "email": r["email"],
        "event_type": r["event_type"],
        "ip_address": r["ip_address"],
        "status": r["status"],
        "details": r["details"],
        "timestamp": r["timestamp"]
    } for r in rows]

    return {"total": len(results), "logs": results}
