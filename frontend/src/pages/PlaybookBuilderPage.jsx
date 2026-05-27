import { useEffect, useState } from 'react';
import {
  fetchCustomPlaybooks, createCustomPlaybook, updateCustomPlaybook,
  deleteCustomPlaybook, dryRunCustomPlaybook,
} from '../api/client';

const STEP_TYPES = [
  { type: 'block_ip',            label: 'Block IP',            icon: '⊘', color: '#B91C1C' },
  { type: 'disable_account',     label: 'Disable Account',     icon: '⏻', color: '#D97706' },
  { type: 'dispatch_alert',      label: 'Dispatch Alert',      icon: '⌬', color: '#2563EB' },
  { type: 'siem_export',         label: 'SIEM Export',         icon: '⛁', color: '#6B8A73' },
  { type: 'set_incident_status', label: 'Set Status',          icon: '◉', color: '#4A5D4F' },
  { type: 'run_webhook',         label: 'Run Webhook',         icon: '↗', color: '#7C3AED' },
  { type: 'delay',               label: 'Delay',               icon: '⏱', color: '#78716C' },
];

const COMMON_ATTACK_TYPES = [
  'sql_injection', 'xss', 'command_injection', 'brute_force',
  'data_exfiltration', 'privilege_escalation', 'malware_upload',
  'directory_traversal', 'ssrf', 'port_scan',
];

const btnPrimary = {
  fontFamily: 'var(--font-mono)', fontSize: 11,
  padding: '8px 16px', borderRadius: 'var(--radius-sm)', border: 'none', cursor: 'pointer',
  background: 'var(--accent)', color: '#ffffff',
  letterSpacing: '0.08em', textTransform: 'uppercase',
  outline: 'none', boxShadow: 'var(--shadow-sm)',
};
const btnGhost = {
  fontFamily: 'var(--font-mono)', fontSize: 10,
  padding: '6px 12px', borderRadius: 4, border: '1px solid var(--border-light)',
  cursor: 'pointer', background: 'transparent', color: 'var(--text-muted)',
  letterSpacing: '0.06em', textTransform: 'uppercase',
};

function StepParamsEditor({ step, onChange }) {
  const setParam = (k, v) => onChange({ ...step, params: { ...(step.params || {}), [k]: v } });
  const params = step.params || {};

  switch (step.type) {
    case 'set_incident_status':
      return (
        <select value={params.status || 'INVESTIGATING'} onChange={e => setParam('status', e.target.value)}
                className="input" style={{ fontSize: 11, padding: '6px 8px', width: 200 }}>
          <option value="INVESTIGATING">INVESTIGATING</option>
          <option value="RESOLVED">RESOLVED</option>
          <option value="FALSE_POSITIVE">FALSE_POSITIVE</option>
        </select>
      );
    case 'dispatch_alert':
      return (
        <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-muted)' }}>
          <input type="checkbox" checked={params.severity_override === 'CRITICAL'}
                 onChange={e => setParam('severity_override', e.target.checked ? 'CRITICAL' : '')} />
          force CRITICAL severity
        </label>
      );
    case 'run_webhook':
      return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6, width: '100%' }}>
          <input className="input" placeholder="https://..." value={params.url || ''}
                 onChange={e => setParam('url', e.target.value)}
                 style={{ fontSize: 11, padding: '6px 8px', fontFamily: 'var(--font-mono)' }} />
          <select value={params.method || 'POST'} onChange={e => setParam('method', e.target.value)}
                  className="input" style={{ fontSize: 11, padding: '6px 8px', width: 100 }}>
            {['POST', 'PUT', 'GET'].map(m => <option key={m} value={m}>{m}</option>)}
          </select>
        </div>
      );
    case 'delay':
      return (
        <input type="number" min="1" max="5" value={params.seconds || 1}
               onChange={e => setParam('seconds', Number(e.target.value))}
               className="input" style={{ fontSize: 11, padding: '6px 8px', width: 100 }} />
      );
    case 'block_ip':
      return (
        <input type="number" min="60" placeholder="duration (s)" value={params.duration_seconds || 3600}
               onChange={e => setParam('duration_seconds', Number(e.target.value))}
               className="input" style={{ fontSize: 11, padding: '6px 8px', width: 160 }} />
      );
    default:
      return <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)' }}>no params</span>;
  }
}

function StepCard({ step, idx, onMove, onRemove, onChange, isDragOver, onDragStart, onDragOver, onDrop }) {
  const meta = STEP_TYPES.find(t => t.type === step.type) || { icon: '•', label: step.type, color: 'var(--text-muted)' };
  return (
    <div
      draggable
      onDragStart={(e) => onDragStart(e, idx)}
      onDragOver={(e) => { e.preventDefault(); onDragOver(idx); }}
      onDrop={(e) => onDrop(e, idx)}
      style={{
        background: 'var(--bg-card)',
        backdropFilter: 'blur(16px)',
        border: `1px solid ${isDragOver ? meta.color : 'var(--border-light)'}`,
        borderRadius: 'var(--radius-sm)', padding: '14px 16px', marginBottom: 10,
        position: 'relative', overflow: 'hidden',
        cursor: 'grab', transition: 'border-color 0.15s',
        boxShadow: 'var(--shadow-sm)',
      }}>
      <div style={{ position: 'absolute', top: 0, left: 0, width: 3, height: '100%', background: meta.color }} />
      <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', letterSpacing: '0.1em', userSelect: 'none' }}>
          ⋮⋮ {String(idx + 1).padStart(2, '0')}
        </div>
        <div style={{ fontSize: 18, color: meta.color }}>{meta.icon}</div>
        <div style={{ flex: 1 }}>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-primary)', letterSpacing: '0.04em' }}>
            {meta.label.toUpperCase()}
          </div>
          <div style={{ marginTop: 8 }}>
            <StepParamsEditor step={step} onChange={onChange} />
          </div>
        </div>
        <div style={{ display: 'flex', gap: 4 }}>
          <button onClick={() => onMove(idx, -1)} disabled={idx === 0} style={iconBtn}>↑</button>
          <button onClick={() => onMove(idx, +1)} style={iconBtn}>↓</button>
          <button onClick={() => onRemove(idx)} style={{ ...iconBtn, color: '#B91C1C' }}>✕</button>
        </div>
      </div>
    </div>
  );
}

const iconBtn = {
  fontFamily: 'var(--font-mono)', fontSize: 11,
  padding: '4px 10px', borderRadius: 4, cursor: 'pointer',
  border: '1px solid var(--border-light)', background: 'transparent',
  color: 'var(--text-muted)',
};

function PlaybookEditor({ playbook, onSave, onCancel, onDelete }) {
  const [name, setName] = useState(playbook?.name || '');
  const [desc, setDesc] = useState(playbook?.description || '');
  const [enabled, setEnabled] = useState(playbook?.enabled ?? true);
  const [attackTypes, setAttackTypes] = useState(playbook?.trigger_attack_types || '');
  const [minRisk, setMinRisk] = useState(playbook?.trigger_min_risk ?? 70);
  const [steps, setSteps] = useState(playbook?.steps || []);
  const [dragOver, setDragOver] = useState(null);
  const [dragIdx, setDragIdx] = useState(null);
  const [saving, setSaving] = useState(false);
  const [err, setErr] = useState('');
  const [dryRun, setDryRun] = useState(null);

  const addStep = (type) => setSteps(s => [...s, { type, params: {} }]);
  const moveStep = (idx, dir) => {
    const j = idx + dir;
    if (j < 0 || j >= steps.length) return;
    const next = [...steps];
    [next[idx], next[j]] = [next[j], next[idx]];
    setSteps(next);
  };
  const removeStep = (idx) => setSteps(s => s.filter((_, i) => i !== idx));
  const updateStep = (idx, newStep) => setSteps(s => s.map((x, i) => i === idx ? newStep : x));

  const onDragStart = (e, idx) => { setDragIdx(idx); e.dataTransfer.effectAllowed = 'move'; };
  const onDrop = (e, idx) => {
    e.preventDefault();
    if (dragIdx === null || dragIdx === idx) { setDragOver(null); return; }
    const next = [...steps];
    const [moved] = next.splice(dragIdx, 1);
    next.splice(idx, 0, moved);
    setSteps(next); setDragIdx(null); setDragOver(null);
  };

  const toggleAttackType = (t) => {
    const cur = attackTypes.split(',').map(x => x.trim()).filter(Boolean);
    const i = cur.indexOf(t);
    const next = i >= 0 ? cur.filter(x => x !== t) : [...cur, t];
    setAttackTypes(next.join(','));
  };
  const isSelected = (t) => attackTypes.split(',').map(x => x.trim()).includes(t);

  const handleSave = async () => {
    if (!name.trim()) { setErr('NAME REQUIRED'); return; }
    setSaving(true); setErr('');
    try {
      const payload = {
        name: name.trim(),
        description: desc,
        enabled,
        trigger_attack_types: attackTypes,
        trigger_min_risk: Number(minRisk),
        steps,
      };
      const saved = playbook?.id
        ? await updateCustomPlaybook(playbook.id, payload)
        : await createCustomPlaybook(payload);
      onSave(saved);
    } catch (e) {
      setErr(e.response?.data?.detail || 'SAVE FAILED');
    }
    setSaving(false);
  };

  const handleDryRun = async () => {
    if (!playbook?.id) { setErr('SAVE FIRST'); return; }
    try {
      const r = await dryRunCustomPlaybook(playbook.id, {
        attack_type: attackTypes.split(',')[0]?.trim() || 'sql_injection',
        risk_score: 90,
        ip: '203.0.113.42',
        user: 'attacker',
        action: 'POST',
        resource: '/api/login',
      });
      setDryRun(r);
    } catch (e) {
      setErr(e.response?.data?.detail || 'DRY RUN FAILED');
    }
  };

  return (
    <div className="page-enter">
      <button onClick={onCancel} style={{ ...btnGhost, marginBottom: 18 }}>← BACK TO LIST</button>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 360px', gap: 20 }}>
        {/* LEFT: Trigger + Steps */}
        <div>
          <div style={{ marginBottom: 24 }}>
            <input className="input" value={name} onChange={e => setName(e.target.value)}
                   placeholder="Playbook name"
                   style={{ fontSize: 18, marginBottom: 8, width: '100%', fontFamily: 'var(--font-display)' }} />
            <textarea className="input" value={desc} onChange={e => setDesc(e.target.value)}
                      placeholder="What does this playbook do?"
                      rows={2} style={{ width: '100%', resize: 'vertical' }} />
          </div>

          {/* Trigger panel */}
          <div style={{ background: 'var(--bg-card)', backdropFilter: 'blur(16px)', border: '1px solid var(--border-light)', borderRadius: 'var(--radius-md)', padding: 20, marginBottom: 20, boxShadow: 'var(--shadow-sm)' }}>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--accent)', letterSpacing: '0.18em', marginBottom: 14, textTransform: 'uppercase' }}>
              ▾ TRIGGER (when this fires)
            </div>

            <div style={{ marginBottom: 14 }}>
              <Label>Match attack types (any of):</Label>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                {COMMON_ATTACK_TYPES.map(t => (
                  <button key={t} onClick={() => toggleAttackType(t)} style={{
                    fontFamily: 'var(--font-mono)', fontSize: 10,
                    padding: '4px 10px', borderRadius: 3, cursor: 'pointer',
                    border: `1px solid ${isSelected(t) ? 'var(--accent)' : 'var(--border-light)'}`,
                    background: isSelected(t) ? 'rgba(74,93,79,0.15)' : 'transparent',
                    color: isSelected(t) ? 'var(--accent)' : 'var(--text-muted)',
                    letterSpacing: '0.04em',
                  }}>{t}</button>
                ))}
              </div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-muted)', marginTop: 6 }}>
                Empty = match any attack type
              </div>
            </div>

            <div>
              <Label>Min risk score: <span style={{ color: 'var(--accent)' }}>{minRisk}</span></Label>
              <input type="range" min="0" max="100" value={minRisk} onChange={e => setMinRisk(Number(e.target.value))}
                     style={{ width: '100%' }} />
            </div>
          </div>

          {/* Steps */}
          <div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--accent)', letterSpacing: '0.18em', marginBottom: 14, textTransform: 'uppercase' }}>
              ▾ STEPS (in order, drag to reorder)
            </div>
            {steps.length === 0 && (
              <div style={{ padding: 30, textAlign: 'center', fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-muted)', border: '1px dashed var(--border-light)', borderRadius: 8 }}>
                No steps yet — add one from the right panel
              </div>
            )}
            {steps.map((s, i) => (
              <StepCard key={i} step={s} idx={i}
                onMove={moveStep} onRemove={removeStep}
                onChange={(ns) => updateStep(i, ns)}
                isDragOver={dragOver === i}
                onDragStart={onDragStart}
                onDragOver={(idx) => setDragOver(idx)}
                onDrop={onDrop} />
            ))}
          </div>
        </div>

        {/* RIGHT: Step palette + actions */}
        <div>
          <div style={{ position: 'sticky', top: 20 }}>
            <div style={{ background: 'var(--bg-card)', backdropFilter: 'blur(16px)', border: '1px solid var(--border-light)', borderRadius: 'var(--radius-md)', padding: 18, marginBottom: 16, boxShadow: 'var(--shadow-sm)' }}>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--accent)', letterSpacing: '0.18em', marginBottom: 12, textTransform: 'uppercase' }}>
                ▸ ADD STEP
              </div>
              {STEP_TYPES.map(s => (
                <button key={s.type} onClick={() => addStep(s.type)} style={{
                  display: 'flex', alignItems: 'center', gap: 10, width: '100%',
                  fontFamily: 'var(--font-mono)', fontSize: 11,
                  padding: '8px 10px', borderRadius: 5, cursor: 'pointer',
                  border: '1px solid var(--border-light)', background: 'transparent',
                  color: 'var(--text-muted)', marginBottom: 6,
                  letterSpacing: '0.06em', textAlign: 'left',
                }}>
                  <span style={{ fontSize: 14, color: s.color }}>{s.icon}</span>
                  <span>{s.label}</span>
                  <span style={{ marginLeft: 'auto', color: 'var(--text-muted)' }}>+</span>
                </button>
              ))}
            </div>

            <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-muted)', marginBottom: 12, padding: '0 4px' }}>
              <input type="checkbox" checked={enabled} onChange={e => setEnabled(e.target.checked)} />
              ENABLED
            </label>

            {err && (
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: '#B91C1C', padding: '6px 10px', marginBottom: 10, background: 'rgba(185,28,28,0.08)', border: '1px solid rgba(185,28,28,0.2)', borderRadius: 4 }}>
                ⚠ {err}
              </div>
            )}

            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              <button onClick={handleSave} disabled={saving} style={btnPrimary}>
                {saving ? 'SAVING...' : (playbook?.id ? 'SAVE CHANGES' : 'CREATE PLAYBOOK')}
              </button>
              {playbook?.id && (
                <>
                  <button onClick={handleDryRun} style={btnGhost}>DRY-RUN AGAINST SAMPLE</button>
                  <button onClick={() => onDelete(playbook.id)} style={{ ...btnGhost, color: '#B91C1C', border: '1px solid rgba(185,28,28,0.3)' }}>DELETE PLAYBOOK</button>
                </>
              )}
            </div>

            {dryRun && (
              <div style={{
                marginTop: 14, fontFamily: 'var(--font-mono)', fontSize: 10,
                padding: 12, borderRadius: 6,
                background: dryRun.matches ? 'rgba(74,93,79,0.08)' : 'rgba(185,28,28,0.06)',
                border: `1px solid ${dryRun.matches ? 'rgba(74,93,79,0.25)' : 'rgba(185,28,28,0.25)'}`,
                color: dryRun.matches ? 'var(--accent)' : '#B91C1C',
              }}>
                {dryRun.matches
                  ? `✓ Trigger matches — would run ${dryRun.would_execute.length} step(s)`
                  : '✗ Sample event does not match this trigger'}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function Label({ children }) {
  return (
    <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-muted)', letterSpacing: '0.18em', marginBottom: 8, textTransform: 'uppercase' }}>
      {children}
    </div>
  );
}

function PlaybookList({ playbooks, onCreate, onEdit }) {
  return (
    <div className="page-enter">
      <div style={{ marginBottom: 28, display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <div className="page-title" style={{ fontFamily: 'var(--font-display)', fontSize: 22, color: 'var(--text-primary)', letterSpacing: 2 }}>
            PLAYBOOK BUILDER
          </div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', letterSpacing: 4, textTransform: 'uppercase', marginTop: 4 }}>
            {playbooks.length} custom playbook{playbooks.length !== 1 ? 's' : ''} · drag-and-drop step composer
          </div>
        </div>
        <button onClick={onCreate} style={btnPrimary}>+ NEW PLAYBOOK</button>
      </div>

      {playbooks.length === 0 ? (
        <div style={{ padding: 60, textAlign: 'center', fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-muted)' }}>
          <div style={{ fontSize: 32, marginBottom: 14, opacity: 0.4 }}>▶</div>
          NO CUSTOM PLAYBOOKS YET
          <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 8, letterSpacing: '0.06em' }}>
            Build SOAR flows that automatically run on matching events
          </div>
        </div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(380px, 1fr))', gap: 16 }}>
          {playbooks.map(pb => (
            <div key={pb.id} onClick={() => onEdit(pb)} style={{
              background: 'var(--bg-card)',
              backdropFilter: 'blur(16px)',
              border: pb.enabled ? '1px solid rgba(74,93,79,0.35)' : '1px solid var(--border-light)',
              borderRadius: 'var(--radius-md)', padding: 20, cursor: 'pointer',
              position: 'relative', overflow: 'hidden',
              boxShadow: 'var(--shadow-sm)',
              transition: 'transform 0.2s var(--ease-out), box-shadow 0.2s var(--ease-out)',
            }}>
              <div style={{ position: 'absolute', top: 0, left: 0, width: 3, height: '100%',
                            background: pb.enabled ? 'var(--accent)' : 'var(--text-muted)' }} />
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 10 }}>
                <div style={{ fontFamily: 'var(--font-display)', fontSize: 16, color: 'var(--text-primary)', letterSpacing: 1 }}>
                  {pb.name}
                </div>
                <span style={{
                  fontFamily: 'var(--font-mono)', fontSize: 9,
                  padding: '2px 8px', borderRadius: 3,
                  background: pb.enabled ? 'rgba(74,93,79,0.1)' : 'rgba(120,113,108,0.1)',
                  border: `1px solid ${pb.enabled ? 'rgba(74,93,79,0.3)' : 'rgba(120,113,108,0.3)'}`,
                  color: pb.enabled ? 'var(--accent)' : 'var(--text-muted)', letterSpacing: '0.08em', textTransform: 'uppercase',
                }}>{pb.enabled ? 'ACTIVE' : 'PAUSED'}</span>
              </div>
              {pb.description && (
                <div style={{ fontFamily: 'var(--font-body)', fontSize: 11, color: 'var(--text-secondary)', marginBottom: 14, lineHeight: 1.5 }}>
                  {pb.description}
                </div>
              )}
              <div style={{ display: 'flex', gap: 16, fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--accent)' }}>
                <span>{pb.step_count} step{pb.step_count !== 1 ? 's' : ''}</span>
                <span>·</span>
                <span>min risk {pb.trigger_min_risk}</span>
                {pb.trigger_attack_types && (
                  <>
                    <span>·</span>
                    <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {pb.trigger_attack_types}
                    </span>
                  </>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default function PlaybookBuilderPage() {
  const [playbooks, setPlaybooks] = useState([]);
  const [editing, setEditing] = useState(null);  // null = list view, {} = new, {id, ...} = edit
  const [loading, setLoading] = useState(true);

  const load = async () => {
    try {
      const d = await fetchCustomPlaybooks();
      setPlaybooks(d.data || []);
    } catch {
      // ignore
    }
    setLoading(false);
  };
  useEffect(() => { load(); }, []);

  const handleSave = async () => { setEditing(null); await load(); };
  const handleDelete = async (id) => {
    if (!confirm('Delete this playbook?')) return;
    await deleteCustomPlaybook(id);
    setEditing(null); await load();
  };

  if (loading) return <div className="loading"><div className="spinner" /><div className="loading-text">Loading...</div></div>;
  if (editing !== null) {
    return <PlaybookEditor playbook={editing.id ? editing : null}
                           onSave={handleSave} onCancel={() => setEditing(null)}
                           onDelete={handleDelete} />;
  }
  return <PlaybookList playbooks={playbooks} onCreate={() => setEditing({})} onEdit={(pb) => setEditing(pb)} />;
}
