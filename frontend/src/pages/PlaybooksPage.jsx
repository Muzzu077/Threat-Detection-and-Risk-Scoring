import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { fetchPlaybooks, previewPlaybook } from '../api/client';

const PLAYBOOK_COLORS = {
  brute_force: { color: 'var(--accent-red)', icon: '🔑', bg: 'rgba(185,28,28,0.08)' },
  sql_injection: { color: 'var(--accent-orange)', icon: '💉', bg: 'rgba(230,168,23,0.08)' },
  data_exfiltration: { color: 'var(--accent-purple)', icon: '📤', bg: 'rgba(168,85,247,0.08)' },
  port_scan: { color: 'var(--accent-yellow)', icon: '🔍', bg: 'rgba(234,179,8,0.08)' },
  xss: { color: 'var(--accent-orange)', icon: '📜', bg: 'rgba(230,168,23,0.08)' },
  privilege_escalation: { color: 'var(--accent-red)', icon: '⬆', bg: 'rgba(185,28,28,0.08)' },
  dos_attack: { color: 'var(--accent-red)', icon: '💥', bg: 'rgba(185,28,28,0.08)' },
  command_injection: { color: 'var(--accent-red)', icon: '⌨', bg: 'rgba(185,28,28,0.08)' },
  directory_traversal: { color: 'var(--accent-yellow)', icon: '📂', bg: 'rgba(234,179,8,0.08)' },
  session_hijacking: { color: 'var(--accent-orange)', icon: '🎭', bg: 'rgba(230,168,23,0.08)' },
  credential_stuffing: { color: 'var(--accent-red)', icon: '🔐', bg: 'rgba(185,28,28,0.08)' },
  ssrf: { color: 'var(--accent-orange)', icon: '🔄', bg: 'rgba(230,168,23,0.08)' },
  malware: { color: 'var(--accent-red)', icon: '🦠', bg: 'rgba(185,28,28,0.08)' },
  insider_threat: { color: 'var(--accent-purple)', icon: '👤', bg: 'rgba(168,85,247,0.08)' },
  default: { color: 'var(--accent-blue)', icon: '🛡', bg: 'rgba(37,99,235,0.08)' },
};

const ACTION_ICONS = {
  block_ip: { icon: '🚫', color: 'var(--accent-red)' },
  disable_account: { icon: '🔒', color: 'var(--accent-orange)' },
  rate_limit: { icon: '⏱', color: 'var(--accent-blue)' },
  firewall_rule: { icon: '🛡', color: 'var(--text-primary)' },
  notify: { icon: '🔔', color: 'var(--accent-purple)' },
};

function PlaybookCard({ playbook, isSelected, onClick }) {
  const cfg = PLAYBOOK_COLORS[playbook.id] || PLAYBOOK_COLORS.default;
  return (
    <div
      onClick={onClick}
      className={isSelected ? 'neon-border' : ''}
      style={{
        background: isSelected ? cfg.bg : 'var(--bg-card)',
        backdropFilter: 'blur(16px)',
        border: `1px solid ${isSelected ? cfg.color : 'var(--border-light)'}`,
        borderRadius: 'var(--radius-lg)',
        padding: '18px 20px',
        cursor: 'pointer',
        transition: 'all 0.3s cubic-bezier(0.4,0,0.2,1)',
        transform: isSelected ? 'scale(1.02)' : 'scale(1)',
        boxShadow: isSelected ? `0 8px 32px ${cfg.bg}` : 'var(--shadow-sm)',
        position: 'relative',
        overflow: 'hidden',
      }}
    >
      <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 2, background: `linear-gradient(90deg, transparent, ${cfg.color}, transparent)`, opacity: isSelected ? 1 : 0.3 }} />

      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 12 }}>
        <span style={{ fontSize: 22, filter: `drop-shadow(0 0 6px ${cfg.bg})` }}>{cfg.icon}</span>
        <div>
          <div style={{ fontFamily: 'var(--font-display)', fontSize: 14, color: isSelected ? cfg.color : 'var(--text-primary)', letterSpacing: 1 }}>
            {playbook.name}
          </div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-muted)', letterSpacing: 2, marginTop: 2 }}>
            {playbook.mitre_technique}
          </div>
        </div>
      </div>

      <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-secondary)', lineHeight: 1.6, marginBottom: 12 }}>
        {playbook.description}
      </div>

      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)' }}>
          {playbook.steps.length} steps
        </span>
        <span style={{
          padding: '3px 10px', borderRadius: 'var(--radius-sm)',
          fontFamily: 'var(--font-mono)', fontSize: 9,
          color: cfg.color, background: cfg.bg,
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
        const actionCfg = ACTION_ICONS[step.action] || { icon: '⚙', color: 'var(--text-muted)' };
        return (
          <div key={i}>
            <div
              className="flow-step"
              style={{
                display: 'flex', alignItems: 'center', gap: 14,
                padding: '14px 18px',
                background: step.will_execute ? `${actionCfg.color}15` : 'transparent',
                borderRadius: 'var(--radius-md)',
                borderLeft: `3px solid ${step.will_execute ? actionCfg.color : 'var(--border-dim)'}`,
                opacity: step.will_execute ? 1 : 0.45,
                transition: 'all 0.3s',
              }}
            >
              {/* Step Number */}
              <div style={{
                width: 28, height: 28, borderRadius: '50%',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                background: step.will_execute ? `${actionCfg.color}15` : 'var(--bg-glass)',
                border: `1px solid ${step.will_execute ? `${actionCfg.color}40` : 'var(--border-dim)'}`,
                fontFamily: 'var(--font-mono)', fontSize: 10,
                color: step.will_execute ? actionCfg.color : 'var(--text-muted)',
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
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: step.will_execute ? 'var(--text-primary)' : 'var(--text-muted)', marginBottom: 3 }}>
                  {step.description}
                </div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)' }}>
                  {step.action.replace('_', ' ').toUpperCase()} &mdash; {step.condition}
                </div>
              </div>

              {/* Status */}
              <div style={{
                padding: '4px 10px', borderRadius: 'var(--radius-sm)',
                fontFamily: 'var(--font-mono)', fontSize: 9,
                letterSpacing: 1,
                background: step.will_execute ? 'var(--bg-glass-heavy)' : 'var(--bg-glass)',
                color: step.will_execute ? 'var(--text-primary)' : 'var(--text-muted)',
                border: `1px solid ${step.will_execute ? 'var(--border-bright)' : 'var(--border-dim)'}`,
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
                    : 'var(--border-dim)',
                }} />
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

function HowItWorks({ open, onToggle }) {
  return (
    <div style={{
      background: 'var(--bg-card)', backdropFilter: 'blur(16px)', border: '1px solid var(--border-light)',
      borderRadius: 'var(--radius-lg)', marginBottom: 20, overflow: 'hidden', boxShadow: 'var(--shadow-sm)'
    }}>
      <button
        onClick={onToggle}
        style={{
          width: '100%', display: 'flex', justifyContent: 'space-between', alignItems: 'center',
          padding: '14px 22px', background: 'transparent', border: 'none',
          fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--accent)',
          letterSpacing: 3, textTransform: 'uppercase', cursor: 'pointer',
        }}
      >
        <span>{open ? '−' : '+'}&nbsp;&nbsp;How SOAR Playbooks Work — Setup &amp; Usage Guide</span>
        <span style={{ fontSize: 9, color: 'var(--text-muted)' }}>{open ? 'COLLAPSE' : 'EXPAND'}</span>
      </button>
      {open && (
        <div style={{
          padding: '6px 22px 22px 22px',
          fontFamily: 'var(--font-mono)', fontSize: 11.5, color: 'var(--text-secondary)',
          lineHeight: 1.75,
        }}>
          <Section title="WHAT IS A PLAYBOOK?">
            A playbook is a named sequence of automated security actions (block IP, disable
            account, rate-limit, generate firewall rule, notify the SOC) that runs when an
            incoming event matches its trigger. Think of it as an &ldquo;if-this-then-that&rdquo;
            rule for security responses.
          </Section>

          <Section title="WHEN DO THEY FIRE?">
            Playbooks fire automatically during ingestion, in two cases:
            <ul style={{ margin: '6px 0 0 22px', padding: 0 }}>
              <li>An event&apos;s detected <code style={c}>attack_type</code> matches a built-in playbook (e.g. <code style={c}>brute_force</code>, <code style={c}>sql_injection</code>) AND</li>
              <li>The event&apos;s computed <code style={c}>risk_score</code> exceeds <strong>90</strong>.</li>
            </ul>
            Each step inside the playbook then has its own threshold — only steps whose
            condition (<code style={c}>risk &ge; N</code>) is satisfied actually execute.
            The slider above lets you preview which steps fire at any given risk score.
          </Section>

          <Section title="HOW TO USE THIS PAGE">
            <ol style={{ margin: '6px 0 0 22px', padding: 0 }}>
              <li>Pick a playbook on the left to see its action flow.</li>
              <li>Drag the <em>Risk Score</em> slider — steps light up when the condition matches and grey out when it doesn&apos;t.</li>
              <li>The MITRE ATT&amp;CK technique tag tells you what attacker behavior the playbook responds to.</li>
            </ol>
          </Section>

          <Section title="ARE THESE REAL ACTIONS?">
            All built-in actions are <strong>simulated</strong> for safety: blocked IPs go to a
            tenant-scoped JSON store, &ldquo;disabled accounts&rdquo; are tracked in the same way,
            firewall rules are emitted as text only. Nothing touches your actual infrastructure.
            Use the <strong>SOAR Auto Response</strong> page to see what was simulated against your tenant.
          </Section>

          <Section title="WANT YOUR OWN PLAYBOOKS?">
            Built-in playbooks cover the 15 most common attack patterns. To add your own
            triggers, conditions, and actions (including real webhooks, SIEM exports, and
            custom alerts), use the{' '}
            <Link to="/playbook-builder" style={{ color: 'var(--accent-blue)', textDecoration: 'underline' }}>
              Playbook Builder
            </Link>
            . Custom playbooks are tenant-scoped and run alongside the built-ins.
          </Section>

          <Section title="LIMITATIONS">
            Built-in playbooks cannot currently be disabled or reconfigured per-tenant — they
            ship as a curated default set. If you need to override behavior, create a custom
            playbook with the same trigger and a higher priority.
          </Section>
        </div>
      )}
    </div>
  );
}

const c = {
  background: 'var(--bg-glass)', padding: '1px 6px', borderRadius: 'var(--radius-sm)',
  border: '1px solid var(--border-dim)', fontSize: 10.5, color: 'var(--text-primary)',
};

function Section({ title, children }) {
  return (
    <div style={{ marginTop: 14 }}>
      <div style={{
        fontSize: 9.5, color: 'var(--accent)', letterSpacing: 2.5, textTransform: 'uppercase',
        marginBottom: 6, fontWeight: 600,
      }}>{title}</div>
      <div>{children}</div>
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
  const [howOpen, setHowOpen] = useState(true);

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
    } catch {
      // ignore
    }
    setPreviewLoading(false);
  };

  const handleRiskChange = async (val) => {
    setRiskScore(val);
    if (selected) {
      setPreviewLoading(true);
      try {
        const result = await previewPlaybook(selected, val);
        setPreview(result);
      } catch {
        // ignore
      }
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
            <div style={{ fontFamily: 'var(--font-display)', fontSize: 22, color: 'var(--text-primary)', letterSpacing: 2 }}>
              &#9889; SOAR PLAYBOOKS
            </div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', letterSpacing: 4, textTransform: 'uppercase', marginTop: 4 }}>
              Automated Response Orchestration &mdash; Conditional Action Flows
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)' }}>
              {playbooks.length} playbooks loaded
            </span>
          </div>
        </div>
      </div>

      <HowItWorks open={howOpen} onToggle={() => setHowOpen(o => !o)} />

      {/* Risk Score Slider */}
      <div style={{
        background: 'var(--bg-card)', backdropFilter: 'blur(16px)', border: '1px solid var(--border-light)',
        borderRadius: 'var(--radius-lg)', padding: '16px 24px', marginBottom: 24, boxShadow: 'var(--shadow-sm)',
        display: 'flex', alignItems: 'center', gap: 20,
      }}>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', letterSpacing: 3, textTransform: 'uppercase', flexShrink: 0 }}>
          Simulate Risk Score
        </div>
        <input type="range" min="0" max="100" value={riskScore}
          onChange={e => handleRiskChange(Number(e.target.value))}
          style={{
            flex: 1, height: 4, appearance: 'none', background: 'var(--border-dim)',
            borderRadius: 2, outline: 'none', cursor: 'pointer',
            accentColor: riskScore >= 80 ? 'var(--accent-red)' : riskScore >= 50 ? 'var(--accent-orange)' : 'var(--text-primary)',
          }}
        />
        <div style={{
          fontFamily: 'var(--font-display)', fontSize: 24, minWidth: 50, textAlign: 'right',
          color: riskScore >= 80 ? 'var(--accent-red)' : riskScore >= 50 ? 'var(--accent-orange)' : 'var(--text-primary)',
          textShadow: `0 0 12px ${riskScore >= 80 ? 'rgba(185,28,28,0.4)' : riskScore >= 50 ? 'rgba(230,168,23,0.3)' : 'rgba(200,200,205,0.3)'}`,
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
          background: 'var(--bg-card)', backdropFilter: 'blur(16px)',
          border: `1px solid ${selected ? cfg.color + '30' : 'var(--border-light)'}`,
          borderRadius: 'var(--radius-lg)', boxShadow: 'var(--shadow-md)',
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
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-muted)', letterSpacing: 2 }}>
                SELECT A PLAYBOOK TO PREVIEW
              </div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-faint)', marginTop: 8 }}>
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
                  <div style={{ fontFamily: 'var(--font-display)', fontSize: 16, color: cfg.color }}>
                    {preview.playbook_name}
                  </div>
                  <div style={{ display: 'flex', gap: 8 }}>
                    <span style={{
                      padding: '4px 12px', borderRadius: 'var(--radius-sm)',
                      fontFamily: 'var(--font-mono)', fontSize: 10,
                      color: 'var(--text-primary)', background: 'var(--bg-glass)',
                      border: '1px solid var(--border-bright)',
                    }}>
                      {preview.actions_to_execute}/{preview.total_steps} ACTIVE
                    </span>
                    {preview.mitre_technique && preview.mitre_technique !== 'N/A' && (
                      <span style={{
                        padding: '4px 12px', borderRadius: 'var(--radius-sm)',
                        fontFamily: 'var(--font-mono)', fontSize: 10,
                        color: 'var(--accent-blue)', background: 'rgba(37,99,235,0.1)',
                        border: '1px solid rgba(37,99,235,0.3)',
                      }}>
                        {preview.mitre_technique}
                      </span>
                    )}
                  </div>
                </div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                  {preview.description}
                </div>
              </div>

              {/* KPI Strip */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12, marginBottom: 24 }}>
                <div style={{ background: 'var(--bg-glass-heavy)', border: '1px solid var(--border-light)', borderRadius: 'var(--radius-md)', padding: '14px 16px', textAlign: 'center' }}>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-muted)', letterSpacing: 2, marginBottom: 6 }}>RISK SCORE</div>
                  <div style={{ fontFamily: 'var(--font-display)', fontSize: 24, color: riskScore >= 80 ? 'var(--accent-red)' : riskScore >= 50 ? 'var(--accent-orange)' : 'var(--text-primary)' }}>
                    {preview.risk_score}
                  </div>
                </div>
                <div style={{ background: 'var(--bg-glass-heavy)', border: '1px solid var(--border-light)', borderRadius: 'var(--radius-md)', padding: '14px 16px', textAlign: 'center' }}>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-muted)', letterSpacing: 2, marginBottom: 6 }}>ACTIONS</div>
                  <div style={{ fontFamily: 'var(--font-display)', fontSize: 24, color: 'var(--text-primary)' }}>
                    {preview.actions_to_execute}
                  </div>
                </div>
                <div style={{ background: 'var(--bg-glass-heavy)', border: '1px solid var(--border-light)', borderRadius: 'var(--radius-md)', padding: '14px 16px', textAlign: 'center' }}>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-muted)', letterSpacing: 2, marginBottom: 6 }}>TOTAL STEPS</div>
                  <div style={{ fontFamily: 'var(--font-display)', fontSize: 24, color: 'var(--accent-blue)' }}>
                    {preview.total_steps}
                  </div>
                </div>
              </div>

              {/* Step Flow */}
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', letterSpacing: 3, textTransform: 'uppercase', marginBottom: 16 }}>
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
