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
  const [notice, setNotice] = useState('');

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
      setErr('');
      setNotice(
        newRole === 'admin'
          ? `${u.email} promoted to ADMIN. They must reload the page (or log out & back in) for admin features to appear in their session.`
          : `${u.email} demoted to USER. Their session will lose admin access on next request.`
      );
      // Refresh self-role too — in case the admin demoted/promoted themselves.
      window.dispatchEvent(new CustomEvent('tp:role-may-have-changed'));
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
        <div style={{ fontFamily: 'var(--font-display)', fontSize: 22, color: 'var(--text-primary)', letterSpacing: 2 }}>
          USER MANAGEMENT
        </div>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', letterSpacing: 4, textTransform: 'uppercase', marginTop: 4 }}>
          {users.length} tenants &middot; {admins} admin{admins !== 1 ? 's' : ''}
        </div>
      </div>

      {err && (
        <div style={{
          fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--accent-red)',
          padding: '10px 16px', marginBottom: 20,
          background: 'rgba(185,28,28,0.08)', border: '1px solid rgba(185,28,28,0.22)', borderRadius: 'var(--radius-sm)',
        }}>&#9888; {err}</div>
      )}

      {notice && (
        <div style={{
          fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--accent-blue)',
          padding: '10px 16px', marginBottom: 20, lineHeight: 1.6,
          background: 'rgba(37,99,235,0.08)', border: '1px solid rgba(37,99,235,0.22)', borderRadius: 'var(--radius-sm)',
          display: 'flex', justifyContent: 'space-between', gap: 12,
        }}>
          <div><span style={{ color: 'var(--text-primary)', marginRight: 8 }}>i</span>{notice}</div>
          <button onClick={() => setNotice('')} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontFamily: 'inherit', fontSize: 11 }}>&times;</button>
        </div>
      )}

      {loading ? (
        <div className="loading"><div className="spinner" /><div className="loading-text">Loading users...</div></div>
      ) : (
        <div style={{ background: 'var(--bg-card)', backdropFilter: 'blur(16px)', border: '1px solid var(--border-light)', borderRadius: 'var(--radius-lg)', overflow: 'hidden', boxShadow: 'var(--shadow-sm)' }}>
          <table className="data-table">
            <thead>
              <tr>{['EMAIL','DISPLAY NAME','ROLE','APPS','JOINED','STATUS',''].map(h => <th key={h}>{h}</th>)}</tr>
            </thead>
            <tbody>
              {users.map(u => (
                <tr key={u.id}>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-primary)' }}>{u.email}</td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-secondary)' }}>{u.display_name || '—'}</td>
                  <td>
                    <span style={{
                      fontFamily: 'var(--font-mono)', fontSize: 9,
                      padding: '3px 10px', borderRadius: 'var(--radius-sm)',
                      background: u.role === 'admin' ? 'rgba(185,28,28,0.08)' : 'rgba(37,99,235,0.08)',
                      border: `1px solid ${u.role === 'admin' ? 'rgba(185,28,28,0.22)' : 'rgba(37,99,235,0.22)'}`,
                      color: u.role === 'admin' ? 'var(--accent-red)' : 'var(--accent-blue)',
                      letterSpacing: '0.08em', textTransform: 'uppercase',
                    }}>{u.role}</span>
                  </td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-muted)' }}>{u.applications_count}</td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-muted)' }}>{formatDate(u.created_at)}</td>
                  <td>
                    <span style={{
                      fontFamily: 'var(--font-mono)', fontSize: 9,
                      padding: '2px 8px', borderRadius: 'var(--radius-sm)',
                      background: u.is_active ? 'rgba(5,150,105,0.08)' : 'rgba(161,161,170,0.08)',
                      border: `1px solid ${u.is_active ? 'rgba(5,150,105,0.22)' : 'rgba(161,161,170,0.22)'}`,
                      color: u.is_active ? 'var(--accent-green)' : 'var(--text-muted)',
                      letterSpacing: '0.08em', textTransform: 'uppercase',
                    }}>{u.is_active ? 'ACTIVE' : 'INACTIVE'}</span>
                  </td>
                  <td style={{ display: 'flex', gap: 6 }}>
                    <button onClick={() => handleToggleRole(u)} style={{
                      fontFamily: 'var(--font-mono)', fontSize: 9, padding: '4px 10px',
                      borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-dim)',
                      background: 'var(--bg-glass)', color: 'var(--text-secondary)', cursor: 'pointer',
                      letterSpacing: '0.06em', textTransform: 'uppercase',
                    }}>{u.role === 'admin' ? 'DEMOTE' : 'PROMOTE'}</button>
                    <button onClick={() => handleDelete(u)} style={{
                      fontFamily: 'var(--font-mono)', fontSize: 9, padding: '4px 10px',
                      borderRadius: 'var(--radius-sm)', border: '1px solid rgba(185,28,28,0.3)',
                      background: 'rgba(185,28,28,0.06)', color: 'var(--accent-red)', cursor: 'pointer',
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
