import sqlite3
import datetime
import uuid
from typing import Optional
from backend.app.config import DB_PATH
from backend.app.engine.rbac_auth import hash_password

def get_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    path = db_path or DB_PATH
    conn = sqlite3.connect(path, timeout=10.0)
    conn.row_factory = sqlite3.Row
    if not path.startswith(":memory:") and "mode=memory" not in path:
        conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def init_db(db_path: Optional[str] = None):
    conn = get_connection(db_path)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        full_name TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        is_active INTEGER DEFAULT 1,
        failed_attempts INTEGER DEFAULT 0,
        locked_until TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS roles (
        id TEXT PRIMARY KEY,
        name TEXT UNIQUE NOT NULL,
        description TEXT NOT NULL,
        is_system INTEGER DEFAULT 0
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS user_roles (
        user_id TEXT NOT NULL,
        role_id TEXT NOT NULL,
        PRIMARY KEY (user_id, role_id),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS token_blacklist (
        jti TEXT PRIMARY KEY,
        revoked_at TEXT NOT NULL,
        reason TEXT DEFAULT ''
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS auth_audit_logs (
        id TEXT PRIMARY KEY,
        user_id TEXT,
        email TEXT NOT NULL,
        event_type TEXT NOT NULL,
        ip_address TEXT DEFAULT '127.0.0.1',
        status TEXT NOT NULL,
        details TEXT DEFAULT '',
        timestamp TEXT NOT NULL
    );
    """)

    # Seed System Roles if empty
    cursor.execute("SELECT COUNT(*) FROM roles;")
    if cursor.fetchone()[0] == 0:
        system_roles = [
            ("role-super-admin", "SUPER_ADMIN", "Full administrative control with unrestricted permissions", 1),
            ("role-admin", "ADMIN", "Directory management, role assignment, and audit oversight", 1),
            ("role-secops", "SECURITY_AUDITOR", "Read-only access to audit trails, access controls, and logs", 1),
            ("role-operator", "OPERATOR", "Standard operations with read/write access to business resources", 1),
            ("role-member", "MEMBER", "Base identity with standard read-only portal access", 1)
        ]
        cursor.executemany("INSERT INTO roles (id, name, description, is_system) VALUES (?, ?, ?, ?);", system_roles)

    # Seed Default Administrator if empty
    cursor.execute("SELECT COUNT(*) FROM users;")
    if cursor.fetchone()[0] == 0:
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        
        # Super Admin
        admin_id = "user-super-admin"
        pwd_hash, salt = hash_password("AdminSecret2026!")
        cursor.execute("""
        INSERT INTO users (id, email, full_name, password_hash, salt, is_active, failed_attempts, created_at, updated_at)
        VALUES (?, 'admin@accesscore.internal', 'Global IAM Administrator', ?, ?, 1, 0, ?, ?);
        """, (admin_id, pwd_hash, salt, now_iso, now_iso))
        cursor.execute("INSERT INTO user_roles (user_id, role_id) VALUES (?, 'role-super-admin');", (admin_id,))

        # Security Auditor
        auditor_id = "user-secops-auditor"
        pwd_hash_aud, salt_aud = hash_password("SecOps2026!")
        cursor.execute("""
        INSERT INTO users (id, email, full_name, password_hash, salt, is_active, failed_attempts, created_at, updated_at)
        VALUES (?, 'secops@accesscore.internal', 'Elena Rostova (SecOps Audit)', ?, ?, 1, 0, ?, ?);
        """, (auditor_id, pwd_hash_aud, salt_aud, now_iso, now_iso))
        cursor.execute("INSERT INTO user_roles (user_id, role_id) VALUES (?, 'role-secops');", (auditor_id,))

    conn.commit()
    return conn
