import { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { fetchIncident, updateIncidentStatus, triggerResponse, fetchMitreMapping } from '../api/client';
import { formatDateTime } from '../utils/helpers';
import { RiskBadge, AttackTypeBadge, StatusBadge, RiskBar } from '../components/Badges';
import AttackTimeline from '../components/AttackTimeline';

const STATUS_OPTIONS = ['OPEN', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE'];

export default function InvestigationPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [incident, setIncident] = useState(null);
  const [loading, setLoading] = useState(true);
  const [newStatus, setNewStatus] = useState('');
  const [respLoading, setRespLoading] = useState(false);
  const [responseResult, setResponseResult] = useState(null);
  const [statusMsg, setStatusMsg] = useState('');
  const [mitre, setMitre] = useState(null);
  const [activeTab, setActiveTab] = useState('details');

  const load = async () => {
    try {
      const data = await fetchIncident(id);
      setIncident(data);
      setNewStatus(data.status);
      // Load MITRE mapping
      const m = await fetchMitreMapping(data.attack_type || 'unknown', data.action || '');
      setMitre(m);
    } catch {}
    setLoading(false);
  };

  useEffect(() => { load(); }, [id]);

  const handleStatusUpdate = async () => {
    await updateIncidentStatus(id, newStatus);
    setStatusMsg('Status updated successfully.');
    setTimeout(() => setStatusMsg(''), 3000);
    load();
  };

  const handleResponse = async () => {
    setRespLoading(true);
    try {
      const res = await triggerResponse(id, true);
      setResponseResult(res);
    } catch {
      setResponseResult({ error: 'Failed to trigger response' });
    }
    setRespLoading(false);
  };

  const getActionIcon = (action) => {
    if (action === 'block_ip') return '[BLOCK]';
    if (action === 'disable_account') return '[LOCK]';
    if (action === 'rate_limit') return '[LIMIT]';
    if (action === 'firewall_rule') return '[FW]';
    return '[ACT]';
  };

  if (loading) return (
    <div className="loading"><div className="spinner"/><div className="loading-text">Loading incident...</div></div>
  );

  if (!incident) return (
    <div className="card p-empty">INCIDENT NOT FOUND</div>
  );

  const log = incident.log_event;

  const TABS = [
    { id: 'details', label: 'Details' },
    { id: 'timeline', label: 'Attack Timeline' },
    { id: 'mitre', label: 'MITRE ATT&CK' },
    { id: 'response', label: 'SOAR Response' },
  ];

  return (
    <div className="fade-in">
      {/* Header */}
      <div className="flex-between mb-24">
        <div>
          <div className="flex gap-12" style={{ alignItems: 'center' }}>
            <button className="btn btn-ghost" onClick={() => navigate('/incidents')}>BACK</button>
            <div className="page-title">INCIDENT INC-{String(incident.id).padStart(4, '0')}</div>
          </div>
          <div className="page-subtitle">Deep Investigation View</div>
        </div>
        <div className="flex gap-8">
          <StatusBadge status={incident.status} />
          <RiskBadge score={incident.risk_score} />
          <AttackTypeBadge type={incident.attack_type} />
        </div>
      </div>

      {/* KPI Strip */}
      <div className="grid-4 mb-24">
        {[
          { label: 'Risk Score', value: `${Math.round(incident.risk_score)}/100`, cls: 'red' },
          { label: 'User', value: incident.user, cls: 'cyan' },
          { label: 'Status', value: incident.status, cls: '' },
          { label: 'Owner', value: incident.owner, cls: '' },
        ].map(c => (
          <div key={c.label} className="metric-card">
            <div className="metric-label">{c.label}</div>
            <div className={`metric-value ${c.cls}`} style={{ fontSize: 20 }}>{c.value}</div>
          </div>
        ))}
      </div>

      {/* Tab Navigation */}
      <div style={{ display: 'flex', gap: 4, marginBottom: 20, borderBottom: '1px solid var(--border-dim)', paddingBottom: 0 }}>
        {TABS.map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            style={{
              padding: '8px 16px',
              background: activeTab === tab.id ? 'rgba(0,255,200,0.1)' : 'transparent',
              border: 'none',
              borderBottom: activeTab === tab.id ? '2px solid var(--accent-cyan)' : '2px solid transparent',
              color: activeTab === tab.id ? 'var(--accent-cyan)' : 'var(--text-muted)',
              fontFamily: 'var(--font-mono)',
              fontSize: 11,
              letterSpacing: '0.08em',
              cursor: 'pointer',
              transition: 'all 0.2s',
              borderRadius: '4px 4px 0 0',
            }}
          >
            {tab.label.toUpperCase()}
          </button>
        ))}
      </div>

      {/* Tab: DETAILS */}
      {activeTab === 'details' && (
        <div className="grid-2">
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            {/* Event Details */}
            <div className="card">
              <div className="section-header"><div className="section-title">Event Details</div></div>
              <table style={{ width: '100%', fontFamily: 'var(--font-mono)', fontSize: 12, borderCollapse: 'collapse' }}>
                <tbody>
                  {[
                    ['Timestamp', formatDateTime(incident.timestamp)],
                    ['Action', incident.action],
                    ['Attack Type', <AttackTypeBadge type={incident.attack_type} />],
                    ...(log ? [
                      ['IP Address', log.ip],
                      ['Country', log.country || 'UNKNOWN'],
                      ['Role', log.role],
                      ['Resource', log.resource],
                      ['Threat Intel Score', `${log.threat_intel_score || 0}%`],
                      ['ML Confidence', `${log.ml_confidence || 0}%`],
                    ] : []),
                  ].map(([key, val]) => (
                    <tr key={key}>
                      <td style={{ padding: '6px 0', color: 'var(--text-muted)', width: '40%', fontSize: 11 }}>{key}</td>
                      <td style={{ padding: '6px 0', color: 'var(--text-primary)', borderBottom: '1px solid var(--border-dim)' }}>{val}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Explanation */}
            {log?.explanation && (
              <div className="card">
                <div className="section-header"><div className="section-title">Rule Explanation</div></div>
                <pre style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-secondary)', whiteSpace: 'pre-wrap', lineHeight: 1.6, margin: 0 }}>
                  {log.explanation}
                </pre>
              </div>
            )}

            {/* AI Summary */}
            {incident.note && (
              <div className="card" style={{ borderColor: 'rgba(0,255,200,0.25)' }}>
                <div className="section-header"><div className="section-title">AI Security Analysis</div></div>
                <div style={{ fontFamily: 'var(--font-body)', fontSize: 13, color: 'var(--text-primary)', lineHeight: 1.7, background: 'rgba(0,255,200,0.04)', borderRadius: 6, padding: '12px 14px' }}>
                  {incident.note}
                </div>
              </div>
            )}
          </div>

          {/* Right: Status + Risk Breakdown */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            <div className="card">
              <div className="section-header"><div className="section-title">Status Management</div></div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                <select className="input" value={newStatus} onChange={e => setNewStatus(e.target.value)}>
                  {STATUS_OPTIONS.map(s => <option key={s} value={s}>{s}</option>)}
                </select>
                <button className="btn btn-primary" onClick={handleStatusUpdate}>UPDATE STATUS</button>
                {statusMsg && <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--accent-cyan)' }}>{statusMsg}</div>}
              </div>
            </div>

            {log && (
              <div className="card">
                <div className="section-header"><div className="section-title">Risk Score Breakdown</div></div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                  {[
                    { label: 'Anomaly Score', val: log.anomaly_score },
                    { label: 'Time Risk', val: log.time_risk },
                    { label: 'Role Risk', val: log.role_risk },
                    { label: 'Resource Risk', val: log.resource_risk },
                  ].map(row => (
                    <div key={row.label}>
                      <div className="flex-between" style={{ marginBottom: 4 }}>
                        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)' }}>{row.label}</span>
                        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-secondary)' }}>{Math.round(row.val || 0)}</span>
                      </div>
                      <RiskBar score={Math.min(100, row.val || 0)} />
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Tab: ATTACK TIMELINE */}
      {activeTab === 'timeline' && (
        <div className="card">
          <div className="section-header flex-between">
            <div className="section-title">Attack Timeline — {incident.user} / {log?.ip || 'N/A'}</div>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)' }}>
              Events within 30 minutes of incident
            </span>
          </div>
          <div style={{ maxHeight: 600, overflowY: 'auto' }}>
            <AttackTimeline incidentId={id} />
          </div>
        </div>
      )}

      {/* Tab: MITRE ATT&CK */}
      {activeTab === 'mitre' && mitre && (
        <div className="grid-2">
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            {/* Main Technique Card */}
            <div className="card" style={{ borderColor: mitre.technique_id ? 'rgba(74,158,255,0.3)' : 'var(--border-dim)' }}>
              <div className="section-header flex-between">
                <div className="section-title">MITRE ATT&CK Mapping</div>
                {mitre.technique_id && (
                  <span style={{ padding: '4px 10px', background: 'rgba(74,158,255,0.1)', border: '1px solid rgba(74,158,255,0.3)', borderRadius: 4, fontFamily: 'var(--font-display)', fontSize: 14, color: '#4a9eff' }}>
                    {mitre.technique_id}
                  </span>
                )}
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                <div>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-muted)', marginBottom: 4, letterSpacing: '0.12em' }}>TACTIC</div>
                  <div style={{ fontFamily: 'var(--font-body)', fontSize: 14, color: '#a855f7' }}>{mitre.tactic}</div>
                </div>
                <div>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-muted)', marginBottom: 4, letterSpacing: '0.12em' }}>TECHNIQUE</div>
                  <div style={{ fontFamily: 'var(--font-body)', fontSize: 14, color: 'var(--text-primary)' }}>{mitre.technique_name}</div>
                </div>
                {mitre.sub_technique && (
                  <div>
                    <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-muted)', marginBottom: 4, letterSpacing: '0.12em' }}>SUB-TECHNIQUE</div>
                    <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: '#4a9eff' }}>{mitre.sub_technique}</div>
                  </div>
                )}
                <div>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-muted)', marginBottom: 4, letterSpacing: '0.12em' }}>DESCRIPTION</div>
                  <div style={{ fontFamily: 'var(--font-body)', fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.7 }}>{mitre.description}</div>
                </div>
              </div>
            </div>

            {/* Mitigation Card */}
            <div className="card" style={{ borderColor: 'rgba(0,255,200,0.2)' }}>
              <div className="section-header"><div className="section-title">Recommended Mitigations</div></div>
              <div style={{ fontFamily: 'var(--font-body)', fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.8 }}>
                {mitre.mitigation}
              </div>
              {mitre.url && (
                <div style={{ marginTop: 16 }}>
                  <a
                    href={mitre.url}
                    target="_blank"
                    rel="noreferrer"
                    style={{
                      fontFamily: 'var(--font-mono)', fontSize: 11, color: '#4a9eff',
                      textDecoration: 'none', borderBottom: '1px solid rgba(74,158,255,0.3)',
                      paddingBottom: 2
                    }}
                  >
                    View on MITRE ATT&CK{mitre.technique_id ? ` (${mitre.technique_id})` : ''}
                  </a>
                </div>
              )}
            </div>
          </div>

          {/* Kill Chain Diagram */}
          <div className="card">
            <div className="section-header"><div className="section-title">Kill Chain Phase</div></div>
            {[
              { phase: 'Reconnaissance', tid: 'T1595', active: mitre.tactic?.includes('Reconnaissance') },
              { phase: 'Initial Access', tid: 'T1190', active: mitre.tactic?.includes('Initial Access') },
              { phase: 'Execution', tid: 'T1059', active: mitre.tactic?.includes('Execution') },
              { phase: 'Credential Access', tid: 'T1110', active: mitre.tactic?.includes('Credential') },
              { phase: 'Discovery', tid: 'T1046', active: mitre.tactic?.includes('Discovery') },
              { phase: 'Privilege Escalation', tid: 'T1068', active: mitre.tactic?.includes('Privilege') },
              { phase: 'Defense Evasion', tid: 'T1036', active: mitre.tactic?.includes('Defense') },
              { phase: 'Exfiltration', tid: 'T1041', active: mitre.tactic?.includes('Exfil') },
              { phase: 'Impact', tid: 'T1498', active: mitre.tactic?.includes('Impact') },
            ].map((phase, idx) => (
              <div
                key={phase.phase}
                style={{
                  display: 'flex', alignItems: 'center', gap: 12,
                  padding: '10px 0', borderBottom: '1px solid var(--border-dim)',
                  animation: `fadeIn 0.3s ease ${idx * 0.05}s both`
                }}
              >
                <div style={{
                  width: 10, height: 10, borderRadius: '50%',
                  background: phase.active ? 'var(--accent-cyan)' : 'var(--bg-elevated)',
                  border: `1px solid ${phase.active ? 'var(--accent-cyan)' : 'var(--border-mid)'}`,
                  boxShadow: phase.active ? 'var(--glow-cyan)' : 'none',
                  flexShrink: 0,
                }} />
                <div style={{ flex: 1 }}>
                  <div style={{
                    fontFamily: 'var(--font-mono)', fontSize: 12,
                    color: phase.active ? 'var(--accent-cyan)' : 'var(--text-muted)',
                    fontWeight: phase.active ? 600 : 400,
                  }}>{phase.phase}</div>
                </div>
                <span style={{
                  fontFamily: 'var(--font-mono)', fontSize: 10,
                  color: phase.active ? '#4a9eff' : 'var(--border-mid)'
                }}>{phase.tid}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Tab: SOAR RESPONSE */}
      {activeTab === 'response' && (
        <div className="grid-2">
          <div className="card">
            <div className="section-header"><div className="section-title">SOAR Automated Response</div></div>
            <p style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-muted)', marginBottom: 12, lineHeight: 1.6 }}>
              Trigger automatic countermeasures: IP blocking, account lock, rate limiting, firewall rules.
            </p>
            <button className="btn btn-danger" onClick={handleResponse} disabled={respLoading} style={{ width: '100%', padding: 14 }}>
              {respLoading ? 'EXECUTING RESPONSE...' : 'TRIGGER RESPONSE ACTIONS'}
            </button>

            {incident.response_actions && !responseResult && (() => {
              try {
                const actions = JSON.parse(incident.response_actions);
                if (actions.length > 0) return (
                  <div style={{ marginTop: 16 }}>
                    <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', marginBottom: 10, letterSpacing: '0.1em' }}>PREVIOUSLY EXECUTED:</div>
                    {actions.map((a, i) => (
                      <div key={i} style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--accent-cyan)', padding: '5px 0', borderBottom: '1px solid var(--border-dim)' }}>
                        [OK] {typeof a === 'string' ? a : a.action}
                      </div>
                    ))}
                  </div>
                );
              } catch {}
              return null;
            })()}

            {responseResult && !responseResult.error && (
              <div style={{ marginTop: 16 }}>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--accent-cyan)', marginBottom: 10, letterSpacing: '0.1em' }}>
                  {responseResult.actions_count} ACTIONS EXECUTED:
                </div>
                {(responseResult.actions_taken || []).map((action, i) => (
                  <div key={i} style={{ background: 'var(--bg-elevated)', borderRadius: 6, padding: '10px 12px', marginBottom: 8, borderLeft: '2px solid var(--accent-cyan)' }}>
                    <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-primary)', marginBottom: 4 }}>
                      {getActionIcon(action.action)} {action.action?.toUpperCase()?.replace('_', ' ')}
                      <span style={{ marginLeft: 8, color: action.status === 'success' ? 'var(--accent-cyan)' : 'var(--accent-amber)' }}>
                        [{action.status}]
                      </span>
                    </div>
                    {action.message && <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)' }}>{action.message}</div>}
                    {action.command && <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: '#4a9eff', marginTop: 4 }}>$ {action.command}</div>}
                  </div>
                ))}
              </div>
            )}
            {responseResult?.error && <div className="login-error" style={{ marginTop: 12 }}>{responseResult.error}</div>}
          </div>

          {/* Risk Breakdown */}
          {log && (
            <div className="card">
              <div className="section-header"><div className="section-title">Risk Score Breakdown</div></div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                {[
                  { label: 'Anomaly Score', val: log.anomaly_score },
                  { label: 'Time Risk', val: log.time_risk },
                  { label: 'Role Risk', val: log.role_risk },
                  { label: 'Resource Risk', val: log.resource_risk },
                ].map(row => (
                  <div key={row.label}>
                    <div className="flex-between" style={{ marginBottom: 4 }}>
                      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)' }}>{row.label}</span>
                      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-secondary)' }}>{Math.round(row.val || 0)}</span>
                    </div>
                    <RiskBar score={Math.min(100, row.val || 0)} />
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
