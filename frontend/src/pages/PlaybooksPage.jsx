import { useEffect, useState } from 'react';
import { fetchPlaybooks, previewPlaybook } from '../api/client';

const PLAYBOOK_COLORS = {
  brute_force: { color: '#f03250', icon: '🔑', bg: 'rgba(240,50,80,0.06)' },
  sql_injection: { color: '#ff8c00', icon: '💉', bg: 'rgba(255,140,0,0.06)' },
  data_exfiltration: { color: '#a855f7', icon: '📤', bg: 'rgba(168,85,247,0.06)' },
  port_scan: { color: '#ffb800', icon: '🔍', bg: 'rgba(255,184,0,0.06)' },
  xss: { color: '#ff8c00', icon: '📜', bg: 'rgba(255,140,0,0.06)' },
  privilege_escalation: { color: '#f03250', icon: '⬆', bg: 'rgba(240,50,80,0.06)' },
  dos_attack: { color: '#f03250', icon: '💥', bg: 'rgba(240,50,80,0.06)' },
  command_injection: { color: '#f03250', icon: '⌨', bg: 'rgba(240,50,80,0.06)' },
  directory_traversal: { color: '#ffb800', icon: '📂', bg: 'rgba(255,184,0,0.06)' },
  session_hijacking: { color: '#ff8c00', icon: '🎭', bg: 'rgba(255,140,0,0.06)' },
  credential_stuffing: { color: '#f03250', icon: '🔐', bg: 'rgba(240,50,80,0.06)' },
  ssrf: { color: '#ff8c00', icon: '🔄', bg: 'rgba(255,140,0,0.06)' },
  malware: { color: '#f03250', icon: '🦠', bg: 'rgba(240,50,80,0.06)' },
  insider_threat: { color: '#a855f7', icon: '👤', bg: 'rgba(168,85,247,0.06)' },
  default: { color: '#4a9eff', icon: '🛡', bg: 'rgba(74,158,255,0.06)' },
};

const ACTION_ICONS = {
  block_ip: { icon: '🚫', color: '#f03250' },
  disable_account: { icon: '🔒', color: '#ffb800' },
  rate_limit: { icon: '⏱', color: '#4a9eff' },
  firewall_rule: { icon: '🛡', color: '#00e5b0' },
  notify: { icon: '🔔', color: '#a855f7' },
};

function PlaybookCard({ playbook, isSelected, onClick }) {
  const cfg = PLAYBOOK_COLORS[playbook.id] || PLAYBOOK_COLORS.default;
  return (
    <div
      onClick={onClick}
      className={isSelected ? 'neon-border' : ''}
      style={{
        background: isSelected ? cfg.bg : '#0c1520',
        border: `1px solid ${isSelected ? cfg.color + '60' : cfg.color + '20'}`,
        borderRadius: 10,
        padding: '18px 20px',
        cursor: 'pointer',
        transition: 'all 0.3s cubic-bezier(0.4,0,0.2,1)',
        transform: isSelected ? 'scale(1.02)' : 'scale(1)',
        boxShadow: isSelected ? `0 8px 32px ${cfg.color}20` : 'none',
        position: 'relative',
        overflow: 'hidden',
      }}
    >
      <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 2, background: `linear-gradient(90deg, transparent, ${cfg.color}, transparent)`, opacity: isSelected ? 1 : 0.3 }} />

      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 12 }}>
        <span style={{ fontSize: 22, filter: `drop-shadow(0 0 6px ${cfg.color}40)` }}>{cfg.icon}</span>
        <div>
          <div style={{ fontFamily: 'Syne Mono, monospace', fontSize: 13, color: isSelected ? cfg.color : '#e8f4f8', letterSpacing: 1 }}>
            {playbook.name}
          </div>
          <div style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 9, color: '#2e5570', letterSpacing: 2, marginTop: 2 }}>
            {playbook.mitre_technique}
          </div>
        </div>
      </div>

      <div style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 11, color: '#6e9ab5', lineHeight: 1.6, marginBottom: 12 }}>
        {playbook.description}
      </div>

      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <span style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 10, color: '#2e5570' }}>
          {playbook.steps.length} steps
        </span>
        <span style={{
          padding: '3px 10px', borderRadius: 4,
          fontFamily: 'IBM Plex Mono, monospace', fontSize: 9,
          color: cfg.color, background: `${cfg.color}15`,
          border: `1px solid ${cfg.color}30`, letterSpacing: 1,
        }}>
          RISK &ge; {playbook.severity_threshold}
        </span>
      </div>
    </div>
  );
}

function StepFlow({ steps, color }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
      {steps.map((step, i) => {
        const actionCfg = ACTION_ICONS[step.action] || { icon: '⚙', color: '#6e9ab5' };
        return (
          <div key={i}>
            <div
              className="flow-step"
              style={{
                display: 'flex', alignItems: 'center', gap: 14,
                padding: '14px 18px',
                background: step.will_execute ? `${actionCfg.color}08` : 'transparent',
                borderRadius: 8,
                borderLeft: `3px solid ${step.will_execute ? actionCfg.color : '#1a3a50'}`,
                opacity: step.will_execute ? 1 : 0.45,
                transition: 'all 0.3s',
              }}
            >
              {/* Step Number */}
              <div style={{
                width: 28, height: 28, borderRadius: '50%',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                background: step.will_execute ? `${actionCfg.color}15` : 'rgba(255,255,255,0.03)',
                border: `1px solid ${step.will_execute ? `${actionCfg.color}40` : '#1a3a50'}`,
                fontFamily: 'IBM Plex Mono, monospace', fontSize: 10,
                color: step.will_execute ? actionCfg.color : '#2e5570',
                flexShrink: 0,
              }}>
                {i + 1}
              </div>

              {/* Icon */}
              <span style={{ fontSize: 18, flexShrink: 0, filter: step.will_execute ? `drop-shadow(0 0 4px ${actionCfg.color}60)` : 'none' }}>
                {actionCfg.icon}
              </span>

              {/* Details */}
              <div style={{ flex: 1 }}>
                <div style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 12, color: step.will_execute ? '#e8f4f8' : '#2e5570', marginBottom: 3 }}>
                  {step.description}
                </div>
                <div style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 10, color: '#2e5570' }}>
                  {step.action.replace('_', ' ').toUpperCase()} &mdash; {step.condition}
                </div>
              </div>

              {/* Status */}
              <div style={{
                padding: '4px 10px', borderRadius: 4,
                fontFamily: 'IBM Plex Mono, monospace', fontSize: 9,
                letterSpacing: 1,
                background: step.will_execute ? 'rgba(0,229,176,0.1)' : 'rgba(255,255,255,0.03)',
                color: step.will_execute ? '#00e5b0' : '#2e5570',
                border: `1px solid ${step.will_execute ? 'rgba(0,229,176,0.3)' : '#1a3a50'}`,
              }}>
                {step.will_execute ? 'EXECUTE' : 'SKIP'}
              </div>
            </div>

            {/* Connector line */}
            {i < steps.length - 1 && (
              <div style={{ display: 'flex', justifyContent: 'center', padding: '0 0 0 32px' }}>
                <div style={{
                  width: 2, height: 16,
                  background: step.will_execute
                    ? `linear-gradient(to bottom, ${actionCfg.color}60, ${ACTION_ICONS[steps[i+1]?.action]?.color || color}30)`
                    : 'rgba(255,255,255,0.04)',
                }} />
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

export default function PlaybooksPage() {
  const [playbooks, setPlaybooks] = useState([]);
  const [selected, setSelected] = useState(null);
  const [preview, setPreview] = useState(null);
  const [riskScore, setRiskScore] = useState(80);
  const [loading, setLoading] = useState(true);
  const [previewLoading, setPreviewLoading] = useState(false);

  useEffect(() => {
    fetchPlaybooks().then(res => {
      setPlaybooks(res.data || []);
      setLoading(false);
    }).catch(() => setLoading(false));
  }, []);

  const handleSelect = async (pb) => {
    setSelected(pb.id);
    setPreviewLoading(true);
    try {
      const result = await previewPlaybook(pb.id, riskScore);
      setPreview(result);
    } catch {}
    setPreviewLoading(false);
  };

  const handleRiskChange = async (val) => {
    setRiskScore(val);
    if (selected) {
      setPreviewLoading(true);
      try {
        const result = await previewPlaybook(selected, val);
        setPreview(result);
      } catch {}
      setPreviewLoading(false);
    }
  };

  if (loading) return <div className="loading"><div className="spinner"/><div className="loading-text">Loading playbooks...</div></div>;

  const cfg = PLAYBOOK_COLORS[selected] || PLAYBOOK_COLORS.default;

  return (
    <div className="page-enter">
      {/* Header */}
      <div style={{ marginBottom: 28 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
          <div>
            <div style={{ fontFamily: 'Syne Mono, monospace', fontSize: 22, color: '#00e5b0', textShadow: '0 0 24px rgba(0,255,200,0.35)', letterSpacing: 2 }}>
              &#9889; SOAR PLAYBOOKS
            </div>
            <div style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 10, color: '#2e5570', letterSpacing: 4, textTransform: 'uppercase', marginTop: 4 }}>
              Automated Response Orchestration &mdash; Conditional Action Flows
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <span style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 10, color: '#2e5570' }}>
              {playbooks.length} playbooks loaded
            </span>
          </div>
        </div>
      </div>

      {/* Risk Score Slider */}
      <div style={{
        background: '#0c1520', border: '1px solid rgba(0,229,176,0.12)',
        borderRadius: 10, padding: '16px 24px', marginBottom: 24,
        display: 'flex', alignItems: 'center', gap: 20,
      }}>
        <div style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 10, color: '#2e5570', letterSpacing: 3, textTransform: 'uppercase', flexShrink: 0 }}>
          Simulate Risk Score
        </div>
        <input type="range" min="0" max="100" value={riskScore}
          onChange={e => handleRiskChange(Number(e.target.value))}
          style={{
            flex: 1, height: 4, appearance: 'none', background: 'rgba(255,255,255,0.06)',
            borderRadius: 2, outline: 'none', cursor: 'pointer',
            accentColor: riskScore >= 80 ? '#f03250' : riskScore >= 50 ? '#ffb800' : '#00e5b0',
          }}
        />
        <div style={{
          fontFamily: 'Syne Mono, monospace', fontSize: 24, minWidth: 50, textAlign: 'right',
          color: riskScore >= 80 ? '#f03250' : riskScore >= 50 ? '#ffb800' : '#00e5b0',
          textShadow: `0 0 12px ${riskScore >= 80 ? 'rgba(240,50,80,0.4)' : riskScore >= 50 ? 'rgba(255,184,0,0.3)' : 'rgba(0,229,176,0.3)'}`,
        }}>
          {riskScore}
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '380px 1fr', gap: 20 }}>
        {/* Playbook List */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {playbooks.map((pb, i) => (
            <div key={pb.id} className="stagger-item" style={{ animationDelay: `${i * 0.06}s` }}>
              <PlaybookCard
                playbook={pb}
                isSelected={selected === pb.id}
                onClick={() => handleSelect(pb)}
              />
            </div>
          ))}
        </div>

        {/* Preview Panel */}
        <div style={{
          background: '#0c1520',
          border: `1px solid ${selected ? cfg.color + '30' : 'rgba(0,229,176,0.1)'}`,
          borderRadius: 12,
          padding: 24,
          position: 'relative',
          overflow: 'hidden',
          minHeight: 400,
        }}>
          {selected && (
            <div style={{
              position: 'absolute', top: 0, left: 0, right: 0, height: 3,
              background: `linear-gradient(90deg, transparent, ${cfg.color}, transparent)`,
            }} />
          )}

          {!selected ? (
            <div style={{
              display: 'flex', flexDirection: 'column', alignItems: 'center',
              justifyContent: 'center', height: '100%', minHeight: 360,
            }}>
              <div style={{ fontSize: 48, opacity: 0.15, marginBottom: 16 }}>&#9889;</div>
              <div style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 12, color: '#2e5570', letterSpacing: 2 }}>
                SELECT A PLAYBOOK TO PREVIEW
              </div>
              <div style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 10, color: '#1a3a50', marginTop: 8 }}>
                Adjust the risk score slider to see conditional actions
              </div>
            </div>
          ) : previewLoading ? (
            <div className="loading"><div className="spinner"/><div className="loading-text">Evaluating playbook...</div></div>
          ) : preview ? (
            <div className="fade-in">
              {/* Preview Header */}
              <div style={{ marginBottom: 24 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
                  <div style={{ fontFamily: 'Syne Mono, monospace', fontSize: 16, color: cfg.color }}>
                    {preview.playbook_name}
                  </div>
                  <div style={{ display: 'flex', gap: 8 }}>
                    <span style={{
                      padding: '4px 12px', borderRadius: 4,
                      fontFamily: 'IBM Plex Mono, monospace', fontSize: 10,
                      color: '#00e5b0', background: 'rgba(0,229,176,0.1)',
                      border: '1px solid rgba(0,229,176,0.3)',
                    }}>
                      {preview.actions_to_execute}/{preview.total_steps} ACTIVE
                    </span>
                    {preview.mitre_technique && preview.mitre_technique !== 'N/A' && (
                      <span style={{
                        padding: '4px 12px', borderRadius: 4,
                        fontFamily: 'IBM Plex Mono, monospace', fontSize: 10,
                        color: '#4a9eff', background: 'rgba(74,158,255,0.1)',
                        border: '1px solid rgba(74,158,255,0.3)',
                      }}>
                        {preview.mitre_technique}
                      </span>
                    )}
                  </div>
                </div>
                <div style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 11, color: '#6e9ab5', lineHeight: 1.6 }}>
                  {preview.description}
                </div>
              </div>

              {/* KPI Strip */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12, marginBottom: 24 }}>
                <div style={{ background: '#101d2a', borderRadius: 8, padding: '14px 16px', textAlign: 'center' }}>
                  <div style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 9, color: '#2e5570', letterSpacing: 2, marginBottom: 6 }}>RISK SCORE</div>
                  <div style={{ fontFamily: 'Syne Mono, monospace', fontSize: 24, color: riskScore >= 80 ? '#f03250' : riskScore >= 50 ? '#ffb800' : '#00e5b0' }}>
                    {preview.risk_score}
                  </div>
                </div>
                <div style={{ background: '#101d2a', borderRadius: 8, padding: '14px 16px', textAlign: 'center' }}>
                  <div style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 9, color: '#2e5570', letterSpacing: 2, marginBottom: 6 }}>ACTIONS</div>
                  <div style={{ fontFamily: 'Syne Mono, monospace', fontSize: 24, color: '#00e5b0' }}>
                    {preview.actions_to_execute}
                  </div>
                </div>
                <div style={{ background: '#101d2a', borderRadius: 8, padding: '14px 16px', textAlign: 'center' }}>
                  <div style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 9, color: '#2e5570', letterSpacing: 2, marginBottom: 6 }}>TOTAL STEPS</div>
                  <div style={{ fontFamily: 'Syne Mono, monospace', fontSize: 24, color: '#4a9eff' }}>
                    {preview.total_steps}
                  </div>
                </div>
              </div>

              {/* Step Flow */}
              <div style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 10, color: '#2e5570', letterSpacing: 3, textTransform: 'uppercase', marginBottom: 16 }}>
                Action Flow
              </div>
              <StepFlow steps={preview.steps} color={cfg.color} />
            </div>
          ) : null}
        </div>
      </div>
    </div>
  );
}
