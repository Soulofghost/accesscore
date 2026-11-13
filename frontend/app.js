// AccessCore IAM & Zero-Trust Access Gateway Frontend
const API_BASE = window.location.origin.includes('http') && !window.location.origin.startsWith('file:')
  ? window.location.origin
  : 'http://localhost:8000';

let allUsers = [];
let allRoles = [];

document.addEventListener('DOMContentLoaded', () => {
  setupNavigation();
  setupModals();
  loadDirectory();
  loadRoles();
  loadAuditLogs();

  document.getElementById('refreshBtn').addEventListener('click', () => {
    loadDirectory();
    loadAuditLogs();
  });
});

function setupNavigation() {
  const navBtns = document.querySelectorAll('.nav-item');
  const tabViews = document.querySelectorAll('.tab-view');
  const title = document.getElementById('viewTitle');
  const subtitle = document.getElementById('viewSubtitle');

  const titles = {
    directory: {
      t: 'Directory & Identity Management',
      s: 'Enterprise identity federation, JWT claim verification, and role assignments'
    },
    roles: {
      t: 'Role-Based Access Control (RBAC)',
      s: 'Hierarchical permission policies, security scopes, and role definitions'
    },
    audit: {
      t: 'Security Audit Trail & SIEM Ingestion',
      s: 'Immutable authentication event logs, brute-force anomalies, and policy change telemetry'
    }
  };

  navBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const tab = btn.dataset.tab;
      navBtns.forEach(b => b.classList.remove('active'));
      tabViews.forEach(v => v.classList.remove('active'));

      btn.classList.add('active');
      const target = document.getElementById(`tab${tab.charAt(0).toUpperCase() + tab.slice(1)}`);
      if (target) target.classList.add('active');

      if (titles[tab]) {
        title.textContent = titles[tab].t;
        subtitle.textContent = titles[tab].s;
      }

      if (tab === 'audit') loadAuditLogs();
      if (tab === 'roles') loadRoles();
      if (tab === 'directory') loadDirectory();
    });
  });
}

function setupModals() {
  const regModal = document.getElementById('registerModal');
  const rolesModal = document.getElementById('editRolesModal');

  document.getElementById('openRegisterModal').addEventListener('click', () => {
    regModal.classList.add('active');
  });

  document.getElementById('closeRegisterBtn').addEventListener('click', () => {
    regModal.classList.remove('active');
  });
  document.getElementById('cancelRegisterBtn').addEventListener('click', () => {
    regModal.classList.remove('active');
  });

  document.getElementById('closeRolesBtn').addEventListener('click', () => {
    rolesModal.classList.remove('active');
  });
  document.getElementById('cancelRolesBtn').addEventListener('click', () => {
    rolesModal.classList.remove('active');
  });

  // Provision User Form
  document.getElementById('registerForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const name = document.getElementById('regName').value.trim();
    const email = document.getElementById('regEmail').value.trim();
    const password = document.getElementById('regPassword').value;

    try {
      const res = await fetch(`${API_BASE}/api/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ full_name: name, email, password })
      });

      if (!res.ok) {
        const err = await res.json();
        alert(err.detail || 'Failed to provision user');
        return;
      }

      regModal.classList.remove('active');
      document.getElementById('registerForm').reset();
      loadDirectory();
      loadAuditLogs();
    } catch (err) {
      alert('Network error connecting to AccessCore backend: ' + err.message);
    }
  });

  // Edit Roles Form
  document.getElementById('editRolesForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const userId = document.getElementById('editUserId').value;
    const checked = Array.from(document.querySelectorAll('#rolesCheckboxes input:checked')).map(i => i.value);

    if (checked.length === 0) {
      alert('User must have at least one assigned role');
      return;
    }

    try {
      const res = await fetch(`${API_BASE}/api/users/${userId}/roles`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ role_names: checked })
      });

      if (!res.ok) {
        const err = await res.json();
        alert(err.detail || 'Failed to update user roles');
        return;
      }

      rolesModal.classList.remove('active');
      loadDirectory();
      loadAuditLogs();
    } catch (err) {
      alert('Error updating roles: ' + err.message);
    }
  });
}

async function loadDirectory() {
  const tbody = document.getElementById('usersTableBody');
  try {
    const res = await fetch(`${API_BASE}/api/users`);
    if (!res.ok) throw new Error('API returned status ' + res.status);
    const data = await res.json();
    allUsers = data.users || [];
    renderUsers(allUsers);
  } catch (err) {
    // Standalone fallback
    allUsers = [
      { id: 'usr-1', email: 'admin@accesscore.internal', full_name: 'Security Ops Admin', roles: ['ADMIN'], is_active: true, is_locked: false, created_at: '2026-11-01T08:00:00Z' },
      { id: 'usr-2', email: 'sec.officer@accesscore.internal', full_name: 'Elena Rostova', roles: ['SECURITY_OFFICER'], is_active: true, is_locked: false, created_at: '2026-11-02T09:15:00Z' },
      { id: 'usr-3', email: 'audit.lead@accesscore.internal', full_name: 'Marcus Vance', roles: ['AUDITOR'], is_active: true, is_locked: false, created_at: '2026-11-03T11:40:00Z' },
      { id: 'usr-4', email: 'dev.eng@accesscore.internal', full_name: 'Priya Sharma', roles: ['MEMBER'], is_active: true, is_locked: false, created_at: '2026-11-05T14:20:00Z' }
    ];
    renderUsers(allUsers);
  }
}

function renderUsers(users) {
  const tbody = document.getElementById('usersTableBody');
  if (users.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted">No provisioned identities found.</td></tr>';
    return;
  }

  tbody.innerHTML = users.map(u => {
    const roleBadges = (u.roles || []).map(r => `<span class="badge badge-role">${escapeHtml(r)}</span>`).join(' ');
    const statusBadge = u.is_locked
      ? '<span class="badge badge-danger">LOCKED (BRUTE-FORCE)</span>'
      : (u.is_active ? '<span class="badge badge-success">ACTIVE</span>' : '<span class="badge badge-muted">SUSPENDED</span>');
    const dateFormatted = u.created_at ? new Date(u.created_at).toLocaleDateString() : 'N/A';

    return `
      <tr>
        <td>
          <div class="user-meta">
            <span class="font-bold">${escapeHtml(u.email)}</span>
            <span class="text-muted text-xs font-mono">${escapeHtml(u.id)}</span>
          </div>
        </td>
        <td>${escapeHtml(u.full_name || 'N/A')}</td>
        <td>${roleBadges}</td>
        <td>${statusBadge}</td>
        <td>${dateFormatted}</td>
        <td>
          <button class="btn btn-sm btn-outline" onclick="openEditRoles('${escapeHtml(u.id)}')">Manage Roles</button>
        </td>
      </tr>
    `;
  }).join('');
}

window.openEditRoles = function(userId) {
  const user = allUsers.find(u => u.id === userId);
  if (!user) return;

  document.getElementById('editUserId').value = user.id;
  document.getElementById('editRolesTitle').textContent = `Manage Roles for ${user.email}`;

  const availableRoles = allRoles.length > 0 ? allRoles.map(r => r.name) : ['ADMIN', 'SECURITY_OFFICER', 'AUDITOR', 'MEMBER'];
  const userRoles = new Set(user.roles || []);

  const container = document.getElementById('rolesCheckboxes');
  container.innerHTML = availableRoles.map(r => `
    <label class="role-check-item">
      <input type="checkbox" value="${escapeHtml(r)}" ${userRoles.has(r) ? 'checked' : ''}>
      <span class="role-check-name">${escapeHtml(r)}</span>
    </label>
  `).join('');

  document.getElementById('editRolesModal').classList.add('active');
};

async function loadRoles() {
  const grid = document.getElementById('rolesGrid');
  try {
    const res = await fetch(`${API_BASE}/api/roles`);
    if (!res.ok) throw new Error('API status ' + res.status);
    const data = await res.json();
    allRoles = data.roles || [];
    renderRoles(allRoles);
  } catch (err) {
    allRoles = [
      { name: 'ADMIN', description: 'Complete system authorization with user creation and key rotation powers.', permissions: ['*'] },
      { name: 'SECURITY_OFFICER', description: 'Manages firewall rules, inspects auth locks, and resets security policies.', permissions: ['security:read', 'security:manage', 'user:unlock'] },
      { name: 'AUDITOR', description: 'Read-only inspection rights for compliance audits, SIEM records, and telemetry.', permissions: ['audit:read', 'user:read'] },
      { name: 'MEMBER', description: 'Standard enterprise staff member with standard API and portal access.', permissions: ['portal:access', 'self:profile'] }
    ];
    renderRoles(allRoles);
  }
}

function renderRoles(roles) {
  const grid = document.getElementById('rolesGrid');
  grid.innerHTML = roles.map(r => {
    const permTags = (r.permissions || []).map(p => `<span class="badge badge-perm">${escapeHtml(p)}</span>`).join(' ');
    return `
      <div class="role-card">
        <div class="role-header">
          <h3>${escapeHtml(r.name)}</h3>
          <span class="badge-role-tag">${r.is_system ? 'SYSTEM DEFAULT' : 'CUSTOM POLICY'}</span>
        </div>
        <p class="role-desc">${escapeHtml(r.description || '')}</p>
        <div class="role-perms-title">Granted Capabilities:</div>
        <div class="role-perms-list">${permTags}</div>
      </div>
    `;
  }).join('');
}

async function loadAuditLogs() {
  const tbody = document.getElementById('auditTableBody');
  try {
    const res = await fetch(`${API_BASE}/api/audit-logs?limit=50`);
    if (!res.ok) throw new Error('API status ' + res.status);
    const data = await res.json();
    renderAuditLogs(data.logs || []);
  } catch (err) {
    const mockLogs = [
      { timestamp: '2026-11-13T13:20:00Z', event_type: 'AUTH_LOGIN', email: 'admin@accesscore.internal', status: 'SUCCESS', details: 'Authenticated via HMAC JWT session' },
      { timestamp: '2026-11-13T13:15:22Z', event_type: 'ROLE_ASSIGNMENT', email: 'dev.eng@accesscore.internal', status: 'SUCCESS', details: 'Assigned roles: MEMBER' },
      { timestamp: '2026-11-13T12:55:04Z', event_type: 'AUTH_LOGIN', email: 'intruder@external.net', status: 'BLOCKED', details: 'Brute-force lockout triggered (5 consecutive failures)' },
      { timestamp: '2026-11-13T12:50:11Z', event_type: 'USER_REGISTRATION', email: 'priya.sharma@accesscore.internal', status: 'SUCCESS', details: 'Identity registered and provisioned' }
    ];
    renderAuditLogs(mockLogs);
  }
}

function renderAuditLogs(logs) {
  const tbody = document.getElementById('auditTableBody');
  if (logs.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted">No security audit events recorded.</td></tr>';
    return;
  }

  tbody.innerHTML = logs.map(l => {
    const statusClass = l.status === 'SUCCESS' ? 'badge-success' : (l.status === 'BLOCKED' ? 'badge-danger' : 'badge-warning');
    const timeFormatted = l.timestamp ? new Date(l.timestamp).toLocaleString() : 'N/A';

    return `
      <tr>
        <td class="font-mono text-xs">${timeFormatted}</td>
        <td><span class="badge badge-event">${escapeHtml(l.event_type)}</span></td>
        <td class="font-bold">${escapeHtml(l.email || 'Anonymous')}</td>
        <td><span class="badge ${statusClass}">${escapeHtml(l.status)}</span></td>
        <td class="text-sm">${escapeHtml(l.details || '')}</td>
      </tr>
    `;
  }).join('');
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
