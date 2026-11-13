"""
Enterprise RBAC & Identity Authentication Engine
PBKDF2 password hashing, cryptographic HMAC-SHA256 token signing, and granular permission resolution.
"""

import hmac
import hashlib
import json
import base64
import os
import uuid
import datetime
from typing import Dict, List, Optional, Tuple, Any

DEFAULT_ROLE_PERMISSIONS: Dict[str, set] = {
    "SUPER_ADMIN": {"*"},
    "ADMIN": {
        "users:read", "users:write", "users:delete",
        "roles:manage", "roles:read", "audit:read",
        "resources:read", "resources:write"
    },
    "SECURITY_AUDITOR": {
        "users:read", "roles:read", "audit:read", "resources:read"
    },
    "OPERATOR": {
        "resources:read", "resources:write", "users:read"
    },
    "MEMBER": {
        "resources:read"
    }
}


def hash_password(password: str, salt: Optional[str] = None) -> Tuple[str, str]:
    """
    Hashes a password with PBKDF2-HMAC-SHA256 using 100,000 iterations.
    """
    if not salt:
        salt = os.urandom(16).hex()
    
    key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        100000
    )
    return key.hex(), salt


def verify_password(password: str, salt: str, expected_hash: str) -> bool:
    """
    Verifies plaintext password against salted PBKDF2 hash using constant-time comparison.
    """
    computed_hash, _ = hash_password(password, salt)
    return hmac.compare_digest(computed_hash, expected_hash)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')


def _b64url_decode(data: str) -> bytes:
    padding = '=' * (4 - (len(data) % 4)) if len(data) % 4 != 0 else ''
    return base64.urlsafe_b64decode((data + padding).encode('utf-8'))


def create_access_token(
    user_id: str,
    email: str,
    roles: List[str],
    secret_key: str,
    expires_in_hours: int = 24
) -> str:
    """
    Generates a cryptographically signed HMAC-SHA256 authentication token.
    """
    header = {"alg": "HS256", "typ": "JWT"}
    now_dt = datetime.datetime.now(datetime.timezone.utc)
    exp_dt = now_dt + datetime.timedelta(hours=expires_in_hours)

    payload = {
        "sub": user_id,
        "email": email,
        "roles": roles,
        "jti": str(uuid.uuid4()),
        "iat": int(now_dt.timestamp()),
        "exp": int(exp_dt.timestamp())
    }

    hdr_bytes = _b64url_encode(json.dumps(header).encode('utf-8'))
    pay_bytes = _b64url_encode(json.dumps(payload).encode('utf-8'))
    signing_input = f"{hdr_bytes}.{pay_bytes}".encode('utf-8')

    signature = hmac.new(secret_key.encode('utf-8'), signing_input, hashlib.sha256).digest()
    sig_bytes = _b64url_encode(signature)

    return f"{hdr_bytes}.{pay_bytes}.{sig_bytes}"


def decode_access_token(token: str, secret_key: str) -> Tuple[bool, Optional[Dict[str, Any]], str]:
    """
    Validates token structure, HMAC signature, and expiration timestamp.
    """
    try:
        parts = token.strip().split('.')
        if len(parts) != 3:
            return False, None, "Malformed token structure"

        hdr_b64, pay_b64, sig_b64 = parts
        signing_input = f"{hdr_b64}.{pay_b64}".encode('utf-8')
        expected_sig = hmac.new(secret_key.encode('utf-8'), signing_input, hashlib.sha256).digest()

        actual_sig = _b64url_decode(sig_b64)
        if not hmac.compare_digest(expected_sig, actual_sig):
            return False, None, "Invalid cryptographic token signature"

        payload = json.loads(_b64url_decode(pay_b64).decode('utf-8'))

        now_ts = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
        if payload.get("exp", 0) < now_ts:
            return False, None, "Token has expired"

        return True, payload, "Valid"
    except Exception as e:
        return False, None, f"Token decode failure: {str(e)}"


def check_permission(
    user_roles: List[str],
    required_permission: str,
    custom_role_map: Optional[Dict[str, List[str]]] = None
) -> bool:
    """
    Resolves permissions across assigned user roles, supporting wildcard grants.
    """
    perms_pool = set()
    role_map = custom_role_map or DEFAULT_ROLE_PERMISSIONS

    for r in user_roles:
        r_upper = r.upper()
        if r_upper in role_map:
            for p in role_map[r_upper]:
                perms_pool.add(p)

    if "*" in perms_pool:
        return True

    return required_permission in perms_pool


def evaluate_lockout(
    failed_attempts: int,
    locked_until_iso: Optional[str],
    max_attempts: int = 5,
    now: Optional[datetime.datetime] = None
) -> Tuple[bool, str]:
    """
    Checks whether account is locked due to consecutive failed authentication attempts.
    """
    current_time = now or datetime.datetime.now(datetime.timezone.utc)
    if current_time.tzinfo is None:
        current_time = current_time.replace(tzinfo=datetime.timezone.utc)

    if locked_until_iso:
        lock_dt = datetime.datetime.fromisoformat(locked_until_iso)
        if lock_dt.tzinfo is None:
            lock_dt = lock_dt.replace(tzinfo=datetime.timezone.utc)

        if current_time < lock_dt:
            mins_left = max(1, int((lock_dt - current_time).total_seconds() // 60))
            return True, f"Account temporarily locked due to failed attempts. Try again in {mins_left} minutes."

    if failed_attempts >= max_attempts:
        return True, f"Account has exceeded maximum failed login attempts ({max_attempts})."

    return False, "Account active"
