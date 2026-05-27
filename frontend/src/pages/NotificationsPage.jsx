import { useEffect, useState } from 'react';
import { fetchNotificationPrefs, updateNotificationPrefs, sendTestAlert, testSiemConnection } from '../api/client';

const SEVERITIES = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
const SEV_COLOR = { CRITICAL: 'var(--accent-red)', HIGH: 'var(--accent-orange)', MEDIUM: 'var(--accent-yellow)', LOW: 'var(--accent-green)' };

function ChannelCard({ icon, title, hint, enabled, onToggle, fieldLabel, fieldValue, onFieldChange,
                      placeholder, onTest, testing, testResult, accentColor }) {
  return (
    <div style={{
      background: 'var(--bg-card)', backdropFilter: 'blur(16px)',
      border: enabled ? `1px solid ${accentColor}65` : '1px solid var(--border-light)',
      borderRadius: 'var(--radius-lg)', padding: 22, marginBottom: 16,
      transition: 'border-color 0.2s', boxShadow: 'var(--shadow-sm)',
      position: 'relative', overflow: 'hidden',
    }}>
      <div style={{ position: 'absolute', top: 0, left: 0, width: 3, height: '100%',
                    background: enabled ? accentColor : 'var(--border-dim)' }} />

      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 16 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <span style={{ fontSize: 24 }}>{icon}</span>
          <div>
            <div style={{ fontFamily: 'var(--font-display)', fontSize: 16, color: 'var(--text-primary)', letterSpacing: 1 }}>{title}</div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', letterSpacing: '0.08em', marginTop: 2 }}>{hint}</div>
          </div>
        </div>
        <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
          <input type="checkbox" checked={enabled} onChange={e => onToggle(e.target.checked)}
                 style={{ width: 16, height: 16, accentColor }} />
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10,
                         color: enabled ? accentColor : 'var(--text-muted)',
                         letterSpacing: '0.1em', textTransform: 'uppercase' }}>
            {enabled ? 'Enabled' : 'Disabled'}
          </span>
        </label>
      </div>

      {/* Destination input */}
      <div style={{ marginBottom: 12 }}>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9,
                      letterSpacing: '0.18em', color: 'var(--text-muted)', marginBottom: 6, textTransform: 'uppercase' }}>
          {fieldLabel}
        </div>
        <input className="input" value={fieldValue} onChange={e => onFieldChange(e.target.value)}
               placeholder={placeholder}
               style={{ width: '100%', fontFamily: 'var(--font-mono)', fontSize: 12 }} />
      </div>

      {/* Test button + result */}
      <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
        <button onClick={onTest} disabled={testing || !fieldValue} className="btn btn-ghost" style={{
          opacity: !fieldValue ? 0.4 : 1,
          cursor: !fieldValue ? 'not-allowed' : 'pointer',
        }}>
          {testing ? 'SENDING...' : 'SEND TEST ALERT'}
        </button>
        {testResult !== null && (
          <span style={{
            fontFamily: 'var(--font-mono)', fontSize: 10,
            color: testResult ? 'var(--accent-green)' : 'var(--accent-red)', letterSpacing: '0.08em',
          }}>
            {testResult ? '✓ DELIVERED' : '✗ FAILED — CHECK CREDENTIALS'}
          </span>
        )}
      </div>
    </div>
  );
}

export default function NotificationsPage() {
  const [prefs, setPrefs] = useState({
    telegram_chat_id: '', whatsapp_number: '', email_address: '',
    enable_telegram: false, enable_whatsapp: false, enable_email: false,
    min_severity: 'HIGH',
    siem_type: '', siem_url: '', siem_token: '', siem_index: 'trustflow',
    enable_siem: false,
  });
  const [siemTokenSet, setSiemTokenSet] = useState(false);
  const [siemTestResult, setSiemTestResult] = useState(null);
  const [siemTesting, setSiemTesting] = useState(false);
  const [loading, setLoading]   = useState(true);
  const [saving, setSaving]     = useState(false);
  const [savedAt, setSavedAt]   = useState(null);
  const [error, setError]       = useState('');
  const [testing, setTesting]   = useState({});
  const [testResult, setTestRes]= useState({});

  const load = async () => {
    try {
      const data = await fetchNotificationPrefs();
      setPrefs({
        telegram_chat_id: data.telegram_chat_id || '',
        whatsapp_number:  data.whatsapp_number  || '',
        email_address:    data.email_address    || '',
        enable_telegram:  !!data.enable_telegram,
        enable_whatsapp:  !!data.enable_whatsapp,
        enable_email:     !!data.enable_email,
        min_severity:     data.min_severity || 'HIGH',
        siem_type:        data.siem_type   || '',
        siem_url:         data.siem_url    || '',
        siem_token:       data.siem_token  || '',
        siem_index:       data.siem_index  || 'trustflow',
        enable_siem:      !!data.enable_siem,
      });
      setSiemTokenSet(!!data.siem_token_set);
    } catch {
      setError('FAILED TO LOAD PREFERENCES');
    }
    setLoading(false);
  };

  useEffect(() => { load(); }, []);

  const update = (k, v) => setPrefs(p => ({ ...p, [k]: v }));

  const handleSave = async () => {
    setSaving(true); setError('');
    try {
      await updateNotificationPrefs(prefs);
      setSavedAt(new Date());
    } catch (e) {
      setError(e.response?.data?.detail || 'SAVE FAILED');
    }
    setSaving(false);
  };

  const handleSiemTest = async () => {
    setSiemTesting(true); setSiemTestResult(null);
    try {
      // Save first
      await updateNotificationPrefs(prefs);
      const r = await testSiemConnection();
      setSiemTestResult(r);
    } catch (e) {
      setSiemTestResult({ ok: false, error: e.response?.data?.detail || 'failed' });
    }
    setSiemTesting(false);
  };

  const handleTest = async (channel) => {
    // Save first so the server-side has the latest credentials
    setTesting(t => ({ ...t, [channel]: true }));
    setTestRes(r => ({ ...r, [channel]: null }));
    try {
      await updateNotificationPrefs(prefs);
      const res = await sendTestAlert(channel);
      setTestRes(r => ({ ...r, [channel]: !!res.delivered }));
    } catch {
      setTestRes(r => ({ ...r, [channel]: false }));
    }
    setTesting(t => ({ ...t, [channel]: false }));
  };

  if (loading) return <div className="loading"><div className="spinner" /><div className="loading-text">Loading...</div></div>;

  return (
    <div className="page-enter" style={{ maxWidth: 720 }}>
      {/* Header */}
      <div style={{ marginBottom: 28 }}>
        <div style={{ fontFamily: 'var(--font-display)', fontSize: 22, color: 'var(--text-primary)', letterSpacing: 2 }}>
          ALERT CHANNELS
        </div>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', letterSpacing: 4, textTransform: 'uppercase', marginTop: 4 }}>
          Where TrustFlow sends your incident notifications
        </div>
      </div>

      {error && (
        <div style={{
          fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--accent-red)',
          padding: '10px 16px', marginBottom: 20,
          background: 'rgba(185,28,28,0.08)', border: '1px solid rgba(185,28,28,0.22)', borderRadius: 'var(--radius-sm)',
        }}>&#9888; {error}</div>
      )}

      {/* Severity threshold */}
      <div style={{
        background: 'var(--bg-card)', backdropFilter: 'blur(16px)', border: '1px solid var(--border-light)',
        borderRadius: 'var(--radius-lg)', padding: 22, marginBottom: 20, boxShadow: 'var(--shadow-sm)'
      }}>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, letterSpacing: '0.18em', color: 'var(--text-muted)', marginBottom: 12, textTransform: 'uppercase' }}>
          Minimum Severity
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          {SEVERITIES.map(s => (
            <button key={s} type="button" onClick={() => update('min_severity', s)} style={{
              flex: 1, fontFamily: 'var(--font-mono)', fontSize: 11,
              padding: '10px 0', borderRadius: 'var(--radius-sm)', cursor: 'pointer',
              border: `1px solid ${prefs.min_severity === s ? SEV_COLOR[s] : 'var(--border-dim)'}`,
              background: prefs.min_severity === s ? `${SEV_COLOR[s]}18` : 'transparent',
              color: prefs.min_severity === s ? SEV_COLOR[s] : 'var(--text-muted)',
              letterSpacing: '0.08em', textTransform: 'uppercase',
            }}>{s}</button>
          ))}
        </div>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', marginTop: 10, lineHeight: 1.5 }}>
          You'll be notified for incidents at this severity <em>or higher</em>.
        </div>
      </div>

      {/* Telegram */}
      <ChannelCard
        icon="✈"
        title="TELEGRAM"
        hint="Inline action buttons let you triage from chat"
        accentColor="#229ED9"
        enabled={prefs.enable_telegram}
        onToggle={v => update('enable_telegram', v)}
        fieldLabel="Chat ID"
        fieldValue={prefs.telegram_chat_id}
        onFieldChange={v => update('telegram_chat_id', v)}
        placeholder="e.g. 123456789  (DM @userinfobot to find yours)"
        onTest={() => handleTest('telegram')}
        testing={testing.telegram}
        testResult={testResult.telegram ?? null}
      />

      {/* WhatsApp */}
      <ChannelCard
        icon="◉"
        title="WHATSAPP"
        hint="Routed via Twilio sandbox or business number"
        accentColor="#25D366"
        enabled={prefs.enable_whatsapp}
        onToggle={v => update('enable_whatsapp', v)}
        fieldLabel="Phone Number (E.164)"
        fieldValue={prefs.whatsapp_number}
        onFieldChange={v => update('whatsapp_number', v)}
        placeholder="+14155552671"
        onTest={() => handleTest('whatsapp')}
        testing={testing.whatsapp}
        testResult={testResult.whatsapp ?? null}
      />

      {/* Email */}
      <ChannelCard
        icon="✉"
        title="EMAIL"
        hint="HTML alert with full incident detail"
        accentColor="var(--accent-blue)"
        enabled={prefs.enable_email}
        onToggle={v => update('enable_email', v)}
        fieldLabel="Email Address"
        fieldValue={prefs.email_address}
        onFieldChange={v => update('email_address', v)}
        placeholder="alerts@yourcompany.com"
        onTest={() => handleTest('email')}
        testing={testing.email}
        testResult={testResult.email ?? null}
      />

      {/* SIEM export */}
      <div style={{
        background: 'var(--bg-card)', backdropFilter: 'blur(16px)',
        border: prefs.enable_siem ? '1px solid rgba(37,99,235,0.45)' : '1px solid var(--border-light)',
        borderRadius: 'var(--radius-lg)', padding: 22, marginBottom: 16,
        position: 'relative', overflow: 'hidden', boxShadow: 'var(--shadow-sm)'
      }}>
        <div style={{ position: 'absolute', top: 0, left: 0, width: 3, height: '100%',
                      background: prefs.enable_siem ? 'var(--accent-blue)' : 'var(--border-dim)' }} />

        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <span style={{ fontSize: 24 }}>⛁</span>
            <div>
              <div style={{ fontFamily: 'var(--font-display)', fontSize: 16, color: 'var(--text-primary)', letterSpacing: 1 }}>
                SIEM EXPORT
              </div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', letterSpacing: '0.08em', marginTop: 2 }}>
                Pipe alerts to Splunk · Elastic · Datadog · Webhook
              </div>
            </div>
          </div>
          <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
            <input type="checkbox" checked={prefs.enable_siem}
                   onChange={e => update('enable_siem', e.target.checked)}
                   style={{ width: 16, height: 16, accentColor: 'var(--accent-blue)' }} />
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10,
                           color: prefs.enable_siem ? 'var(--accent-blue)' : 'var(--text-muted)',
                           letterSpacing: '0.1em', textTransform: 'uppercase' }}>
              {prefs.enable_siem ? 'Enabled' : 'Disabled'}
            </span>
          </label>
        </div>

        <div style={{ marginBottom: 14 }}>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, letterSpacing: '0.18em', color: 'var(--text-muted)', marginBottom: 6, textTransform: 'uppercase' }}>
            Target
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            {['', 'splunk', 'elastic', 'datadog', 'webhook'].map(t => (
              <button key={t || 'none'} type="button" onClick={() => update('siem_type', t)} style={{
                flex: 1, fontFamily: 'var(--font-mono)', fontSize: 11,
                padding: '8px 0', borderRadius: 'var(--radius-sm)', cursor: 'pointer',
                border: `1px solid ${prefs.siem_type === t ? 'var(--accent-blue)' : 'var(--border-dim)'}`,
                background: prefs.siem_type === t ? 'rgba(37,99,235,0.15)' : 'transparent',
                color: prefs.siem_type === t ? 'var(--accent-blue)' : 'var(--text-muted)',
                letterSpacing: '0.08em', textTransform: 'uppercase',
              }}>{t || 'none'}</button>
            ))}
          </div>
        </div>

        {prefs.siem_type && (
          <>
            <div style={{ marginBottom: 12 }}>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, letterSpacing: '0.18em', color: 'var(--text-muted)', marginBottom: 6, textTransform: 'uppercase' }}>
                {prefs.siem_type === 'datadog' ? 'API Endpoint (optional)' : 'URL'}
              </div>
              <input className="input" value={prefs.siem_url} onChange={e => update('siem_url', e.target.value)}
                     placeholder={
                       prefs.siem_type === 'splunk'  ? 'https://splunk.example.com:8088' :
                       prefs.siem_type === 'elastic' ? 'https://elastic.example.com:9200' :
                       prefs.siem_type === 'datadog' ? 'https://http-intake.logs.datadoghq.com (default)' :
                                                      'https://your.webhook.example.com/trustflow'
                     }
                     style={{ width: '100%', fontSize: 12, fontFamily: 'var(--font-mono)' }} />
            </div>

            <div style={{ marginBottom: 12 }}>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, letterSpacing: '0.18em', color: 'var(--text-muted)', marginBottom: 6, textTransform: 'uppercase' }}>
                {prefs.siem_type === 'datadog' ? 'API Key' : 'Auth Token'}
                {siemTokenSet && (
                  <span style={{ marginLeft: 8, color: 'var(--accent-green)', textTransform: 'none', letterSpacing: 0 }}>
                    ✓ saved (leave masked value to keep)
                  </span>
                )}
              </div>
              <input className="input" type="password" value={prefs.siem_token}
                     onChange={e => update('siem_token', e.target.value)}
                     placeholder={siemTokenSet ? '(leave to keep saved token)' : 'Splunk HEC token / API key / Bearer token'}
                     style={{ width: '100%', fontSize: 12, fontFamily: 'var(--font-mono)' }} />
            </div>

            {(prefs.siem_type === 'splunk' || prefs.siem_type === 'elastic') && (
              <div style={{ marginBottom: 14 }}>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, letterSpacing: '0.18em', color: 'var(--text-muted)', marginBottom: 6, textTransform: 'uppercase' }}>
                  Index
                </div>
                <input className="input" value={prefs.siem_index} onChange={e => update('siem_index', e.target.value)}
                       placeholder="trustflow" style={{ width: '100%', fontSize: 12, fontFamily: 'var(--font-mono)' }} />
              </div>
            )}

            <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
              <button onClick={handleSiemTest} disabled={siemTesting || !prefs.siem_type} className="btn btn-ghost">
                {siemTesting ? 'TESTING...' : 'TEST CONNECTION'}
              </button>
              {siemTestResult && (
                <span style={{
                  fontFamily: 'var(--font-mono)', fontSize: 10,
                  color: siemTestResult.ok ? 'var(--accent-green)' : 'var(--accent-red)', letterSpacing: '0.08em',
                }}>
                  {siemTestResult.ok
                    ? `✓ HEARTBEAT DELIVERED (HTTP ${siemTestResult.status})`
                    : `✗ ${siemTestResult.error || `HTTP ${siemTestResult.status} ${(siemTestResult.body || '').slice(0, 60)}`}`}
                </span>
              )}
            </div>
          </>
        )}
      </div>

      {/* Save bar */}
      <div style={{
        marginTop: 24, display: 'flex', gap: 12, alignItems: 'center', justifyContent: 'flex-end',
      }}>
        {savedAt && (
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--accent-green)', letterSpacing: '0.08em' }}>
            ✓ SAVED {savedAt.toLocaleTimeString('en-US', { hour12: false })}
          </span>
        )}
        <button onClick={handleSave} disabled={saving} className="btn btn-primary">
          {saving ? 'SAVING...' : 'SAVE PREFERENCES'}
        </button>
      </div>
    </div>
  );
}
