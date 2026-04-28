import { useEffect, useState } from 'react';
import { fetchAdminUsers, setUserRole, deleteUser } from '../api/client';

function formatDate(s) {
  if (!s) return '—';
  return new Date(s).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
}

export default function AdminUsersPage() {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState('');

  const load = async () => {
    try {
      const data = await fetchAdminUsers();
      setUsers(data.data || []);
    } catch {
      setErr('FAILED TO LOAD USERS');
    }
    setLoading(false);
  };

  useEffect(() => { load(); }, []);

  const handleToggleRole = async (u) => {
    const newRole = u.role === 'admin' ? 'user' : 'admin';
    if (!confirm(`Change ${u.email} to ${newRole.toUpperCase()}?`)) return;
    try {
      await setUserRole(u.id, newRole);
      load();
    } catch (e) {
      setErr(e.response?.data?.detail || 'FAILED TO UPDATE ROLE');
    }
  };

  const handleDelete = async (u) => {
    if (!confirm(`PERMANENTLY delete ${u.email}?\n\nThis removes the user and ALL their data: API keys, applications, events, incidents, playbooks, alert prefs.\n\nThis cannot be undone.`)) return;
    try {
      await deleteUser(u.id);
      load();
    } catch (e) {
      setErr(e.response?.data?.detail || 'FAILED TO DELETE USER');
    }
  };

  const admins = users.filter(u => u.role === 'admin').length;

  return (
    <div className="page-enter">
      <div style={{ marginBottom: 28 }}>
        <div style={{ fontFamily: 'Syne Mono, monospace', fontSize: 22, color: '#ffffff', textShadow: '0 0 24px rgba(255,255,255,0.35)', letterSpacing: 2 }}>
          USER MANAGEMENT
        </div>
        <div style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 10, color: '#555555', letterSpacing: 4, textTransform: 'uppercase', marginTop: 4 }}>
          {users.length} tenants &middot; {admins} admin{admins !== 1 ? 's' : ''}
        </div>
      </div>

      {err && (
        <div style={{
          fontFamily: 'IBM Plex Mono, monospace', fontSize: 12, color: '#e53e3e',
          padding: '10px 16px', marginBottom: 20,
          background: 'rgba(229,62,62,0.08)', border: '1px solid rgba(229,62,62,0.2)', borderRadius: 6,
        }}>&#9888; {err}</div>
      )}

      {loading ? (
        <div className="loading"><div className="spinner" /><div className="loading-text">Loading users...</div></div>
      ) : (
        <div style={{ background: '#0a0a0a', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 10, overflow: 'hidden' }}>
          <table className="data-table">
            <thead>
              <tr>{['EMAIL','DISPLAY NAME','ROLE','APPS','JOINED','STATUS',''].map(h => <th key={h}>{h}</th>)}</tr>
            </thead>
            <tbody>
              {users.map(u => (
                <tr key={u.id}>
                  <td style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 12, color: '#ffffff' }}>{u.email}</td>
                  <td style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 11, color: '#e8f4f8' }}>{u.display_name || '—'}</td>
                  <td>
                    <span style={{
                      fontFamily: 'IBM Plex Mono, monospace', fontSize: 9,
                      padding: '3px 10px', borderRadius: 3,
                      background: u.role === 'admin' ? 'rgba(229,62,62,0.12)' : 'rgba(122,155,176,0.12)',
                      border: `1px solid ${u.role === 'admin' ? 'rgba(229,62,62,0.3)' : 'rgba(122,155,176,0.3)'}`,
                      color: u.role === 'admin' ? '#e53e3e' : '#7a9bb0',
                      letterSpacing: '0.08em', textTransform: 'uppercase',
                    }}>{u.role}</span>
                  </td>
                  <td style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 12, color: '#a0a0a0' }}>{u.applications_count}</td>
                  <td style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 11, color: '#555555' }}>{formatDate(u.created_at)}</td>
                  <td>
                    <span style={{
                      fontFamily: 'IBM Plex Mono, monospace', fontSize: 9,
                      padding: '2px 8px', borderRadius: 3,
                      background: u.is_active ? 'rgba(72,187,120,0.1)' : 'rgba(85,85,85,0.1)',
                      border: `1px solid ${u.is_active ? 'rgba(72,187,120,0.3)' : 'rgba(85,85,85,0.3)'}`,
                      color: u.is_active ? '#48bb78' : '#a0a0a0',
                      letterSpacing: '0.08em', textTransform: 'uppercase',
                    }}>{u.is_active ? 'ACTIVE' : 'INACTIVE'}</span>
                  </td>
                  <td style={{ display: 'flex', gap: 6 }}>
                    <button onClick={() => handleToggleRole(u)} style={{
                      fontFamily: 'IBM Plex Mono, monospace', fontSize: 9, padding: '4px 10px',
                      borderRadius: 3, border: '1px solid rgba(255,255,255,0.15)',
                      background: 'rgba(255,255,255,0.04)', color: '#a0a0a0', cursor: 'pointer',
                      letterSpacing: '0.06em', textTransform: 'uppercase',
                    }}>{u.role === 'admin' ? 'DEMOTE' : 'PROMOTE'}</button>
                    <button onClick={() => handleDelete(u)} style={{
                      fontFamily: 'IBM Plex Mono, monospace', fontSize: 9, padding: '4px 10px',
                      borderRadius: 3, border: '1px solid rgba(229,62,62,0.3)',
                      background: 'rgba(229,62,62,0.06)', color: '#e53e3e', cursor: 'pointer',
                      letterSpacing: '0.06em', textTransform: 'uppercase',
                    }}>DELETE</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
