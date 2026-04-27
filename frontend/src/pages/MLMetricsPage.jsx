import { useEffect, useState } from 'react';
import { fetchMLMetrics, fetchExplainability, fetchModelDrift, fetchAdversarialResults, runAdversarialTests } from '../api/client';
import { RadarChart, Radar, PolarGrid, PolarAngleAxis, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, Cell } from 'recharts';

const METRIC_COLOR = { Accuracy: '#ffffff', Precision: '#63b3ed', Recall: '#e6a817', 'F1 Score': '#ed8936' };

export default function MLMetricsPage() {
  const [metrics, setMetrics] = useState(null);
  const [shap, setShap] = useState(null);
  const [drift, setDrift] = useState(null);
  const [adversarial, setAdversarial] = useState(null);
  const [advLoading, setAdvLoading] = useState(false);
  const [advStatus, setAdvStatus] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([
      fetchMLMetrics(),
      fetchExplainability(),
      fetchModelDrift().catch(() => null),
      fetchAdversarialResults().catch(() => null),
    ]).then(([m, s, d, a]) => {
      setMetrics(m);
      setShap(s);
      setDrift(d);
      setAdversarial(a);
      setLoading(false);
    }).catch(() => setLoading(false));
  }, []);

  if (loading) return <div className="loading"><div className="spinner"/><div className="loading-text">Loading ML metrics...</div></div>;

  if (!metrics || metrics.message) return (
    <div className="page-enter">
      <div className="page-title mb-24">◎ ML METRICS</div>
      <div className="card p-empty">
        <div>No ML metrics found.</div>
        <div style={{ marginTop: 12, fontFamily: 'var(--font-mono)', fontSize: 11 }}>
          Run: <span style={{ color: 'var(--accent-cyan)' }}>python utils/train_ml_engine.py</span>
        </div>
      </div>
    </div>
  );

  const summaryMetrics = [
    { name: 'Accuracy', value: metrics.accuracy },
    { name: 'Precision', value: metrics.precision },
    { name: 'Recall', value: metrics.recall },
    { name: 'F1 Score', value: metrics.f1_score },
  ];

  const radarData = summaryMetrics.map(m => ({ metric: m.name, value: m.value }));

  // Per-class metrics from classification report
  const classReport = metrics.classification_report || {};
  const classes = (metrics.classes || []).filter(c => classReport[c]);
  const classData = classes.map(cls => ({
    name: cls.replace('_', ' '),
    precision: Math.round((classReport[cls]?.precision || 0) * 100),
    recall: Math.round((classReport[cls]?.recall || 0) * 100),
    f1: Math.round((classReport[cls]?.['f1-score'] || 0) * 100),
  }));

  // Confusion matrix (training) + live matrix (real-time from DB)
  const confMatrix = metrics.confusion_matrix || [];
  const live = metrics.live_matrix || null;

  return (
    <div className="page-enter">
      <div className="flex-between mb-24">
        <div>
          <div className="page-title">◎ ML METRICS</div>
          <div className="page-subtitle">{metrics.model_type} Classifier — Performance Analysis</div>
        </div>
        <div style={{ padding: '6px 14px', background: 'rgba(255,255,255,0.08)', border: '1px solid var(--border-mid)', borderRadius: 5, fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--accent-cyan)' }}>
          {metrics.model_type?.toUpperCase()}
        </div>
      </div>

      {/* Model Health / Drift */}
      {drift && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 1fr', gap: 14, marginBottom: 24 }}>
          <div className="metric-card">
            <div className="metric-label">Model Drift Score</div>
            <div className="metric-value" style={{ color: drift.drift_score > 30 ? '#e53e3e' : drift.drift_score > 10 ? '#e6a817' : '#ffffff' }}>
              {drift.drift_score || 0}%
            </div>
          </div>
          <div className="metric-card">
            <div className="metric-label">False Positive Rate</div>
            <div className="metric-value" style={{ color: drift.fp_rate > 15 ? '#e53e3e' : '#ffffff' }}>
              {drift.fp_rate || 0}%
            </div>
          </div>
          <div className="metric-card">
            <div className="metric-label">Total Feedback</div>
            <div className="metric-value cyan">{drift.total_feedback || 0}</div>
          </div>
          <div className="metric-card">
            <div className="metric-label">Status</div>
            <div className="metric-value" style={{ fontSize: 14, color: drift.needs_retraining ? '#e53e3e' : '#ffffff' }}>
              {drift.needs_retraining ? 'RETRAIN NEEDED' : 'HEALTHY'}
            </div>
          </div>
        </div>
      )}

      {drift && drift.recommendation && (
        <div style={{ marginBottom: 24, padding: '12px 18px', borderRadius: 8, background: drift.needs_retraining ? 'rgba(229,62,62,0.07)' : 'rgba(255,255,255,0.04)', border: `1px solid ${drift.needs_retraining ? 'rgba(229,62,62,0.3)' : 'rgba(255,255,255,0.15)'}`, fontFamily: 'var(--font-mono)', fontSize: 11, color: drift.needs_retraining ? '#fc8181' : '#ffffff' }}>
          {drift.needs_retraining ? '\u26A0' : '\u2713'} {drift.recommendation}
        </div>
      )}

      {/* Summary KPIs */}
      {/* KPI Explanations */}
      <div style={{ marginBottom: 16, padding: '14px 18px', borderRadius: 8, background: 'rgba(74,158,255,0.04)', border: '1px solid rgba(74,158,255,0.12)', fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-muted)', lineHeight: 1.8 }}>
        <span style={{ color: '#63b3ed', fontWeight: 600 }}>What do these numbers mean?</span><br/>
        <span style={{ color: '#ffffff' }}>Accuracy</span> = Of all predictions, how many were correct? (97% = 97 out of 100 right)<br/>
        <span style={{ color: '#63b3ed' }}>Precision</span> = When the model says "attack", how often is it really an attack? (High = few false alarms)<br/>
        <span style={{ color: '#e6a817' }}>Recall</span> = Of all real attacks, how many did the model catch? (High = few missed attacks)<br/>
        <span style={{ color: '#ed8936' }}>F1 Score</span> = The balance between Precision and Recall. Best single number to judge model quality.
      </div>
      <div className="grid-4 mb-24">
        {summaryMetrics.map(m => (
          <div key={m.name} className="metric-card">
            <div className="metric-label">{m.name}</div>
            <div className="metric-value cyan">{m.value}%</div>
            <div style={{ height: 4, background: 'var(--bg-elevated)', borderRadius: 2, marginTop: 8 }}>
              <div style={{ width: `${m.value}%`, height: '100%', background: METRIC_COLOR[m.name], borderRadius: 2 }} />
            </div>
          </div>
        ))}
      </div>

      <div className="grid-2 mb-24">
        {/* Radar Chart */}
        <div className="chart-container">
          <div className="chart-title">Model Performance Radar</div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-muted)', marginBottom: 8, marginTop: -8 }}>
            A perfect model fills the entire diamond. Dips show weaknesses.
          </div>
          <ResponsiveContainer width="100%" height={240}>
            <RadarChart data={radarData}>
              <PolarGrid stroke="rgba(255,255,255,0.1)" />
              <PolarAngleAxis dataKey="metric" tick={{ fill: 'var(--text-muted)', fontSize: 11, fontFamily: 'var(--font-mono)' }} />
              <Radar name="Score" dataKey="value" stroke="var(--accent-cyan)" fill="var(--accent-cyan)" fillOpacity={0.12} />
            </RadarChart>
          </ResponsiveContainer>
        </div>

        {/* Per-class F1 chart */}
        <div className="chart-container">
          <div className="chart-title">F1-Score by Attack Class</div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-muted)', marginBottom: 8, marginTop: -8 }}>
            Shows how well the model detects each specific attack type. Longer bars = better detection.
          </div>
          <ResponsiveContainer width="100%" height={240}>
            <BarChart data={classData} layout="vertical" margin={{ top: 0, right: 0, left: 10, bottom: 0 }}>
              <XAxis type="number" domain={[0, 100]} tick={{ fill: 'var(--text-muted)', fontSize: 9 }} axisLine={false} tickLine={false} />
              <YAxis type="category" dataKey="name" tick={{ fill: 'var(--text-secondary)', fontSize: 10, fontFamily: 'var(--font-mono)' }} axisLine={false} tickLine={false} width={100} />
              <Tooltip formatter={(v) => `${v}%`} contentStyle={{ background: 'var(--bg-elevated)', border: '1px solid var(--border-mid)', borderRadius: 6, fontFamily: 'var(--font-mono)', fontSize: 11 }} />
              <Bar dataKey="f1" radius={[0, 2, 2, 0]} name="F1">
                {classData.map((_, i) => <Cell key={i} fill={['#e53e3e','#ed8936','#e6a817','#ffffff','#63b3ed'][i % 5]} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Per-class Precision/Recall/F1 Table */}
      <div className="card mb-24">
        <div className="section-header">
          <div className="section-title">Classification Report — Per Class</div>
        </div>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', marginBottom: 14, lineHeight: 1.7, padding: '0 0 12px', borderBottom: '1px solid var(--border-dim)' }}>
          Each row = one attack type. <span style={{ color: '#63b3ed' }}>Precision</span> = "When I say it's this attack, am I right?" <span style={{ color: '#e6a817' }}>Recall</span> = "Of all real instances, how many did I catch?" <span style={{ color: '#ffffff' }}>F1</span> = Balance of both. <span style={{ color: 'var(--text-secondary)' }}>Support</span> = Number of test samples for this class.
        </div>
        <table className="data-table">
          <thead>
            <tr>
              <th>Class</th>
              <th>Precision</th>
              <th>Recall</th>
              <th>F1-Score</th>
              <th>Support</th>
            </tr>
          </thead>
          <tbody>
            {classData.map((cls, i) => (
              <tr key={cls.name}>
                <td style={{ color: 'var(--accent-cyan)', fontFamily: 'var(--font-mono)' }}>{cls.name}</td>
                <td style={{ color: '#63b3ed' }}>{cls.precision}%</td>
                <td style={{ color: '#e6a817' }}>{cls.recall}%</td>
                <td style={{ color: '#ffffff' }}>{cls.f1}%</td>
                <td style={{ color: 'var(--text-muted)' }}>{classReport[classes[i]]?.support || '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Confusion Matrix */}
      {confMatrix.length > 0 && (
        <div className="card">
          <div className="section-header">
            <div className="section-title">Confusion Matrix</div>
          </div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', marginBottom: 16, lineHeight: 1.8, padding: '0 0 14px', borderBottom: '1px solid var(--border-dim)' }}>
            <span style={{ color: '#63b3ed', fontWeight: 600 }}>How to read this:</span> Each <span style={{ color: 'var(--accent-amber)' }}>row</span> is the <strong>actual</strong> attack type. Each <span style={{ color: 'var(--accent-cyan)' }}>column</span> is what the model <strong>predicted</strong>.<br/>
            <span style={{ color: '#ffffff' }}>Green diagonal</span> = Correct predictions (model got it right).<br/>
            <span style={{ color: '#fc8181' }}>Red off-diagonal</span> = Mistakes (model confused one attack for another).<br/>
            A perfect model would have numbers ONLY on the green diagonal and zeros everywhere else.
          </div>
          <div style={{ overflowX: 'auto' }}>
            <table style={{ borderCollapse: 'collapse', fontFamily: 'var(--font-mono)', fontSize: 11 }}>
              <thead>
                <tr>
                  <th style={{ padding: '8px 12px', color: 'var(--text-muted)', fontSize: 10 }}>Pred →<br/>True ↓</th>
                  {classes.map(c => (
                    <th key={c} style={{ padding: '8px 12px', color: 'var(--accent-cyan)', fontSize: 10, letterSpacing: '0.05em' }}>
                      {c.replace('_', ' ')}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {confMatrix.map((row, i) => (
                  <tr key={i}>
                    <td style={{ padding: '8px 12px', color: 'var(--accent-amber)', fontSize: 10 }}>{classes[i]?.replace('_', ' ')}</td>
                    {row.map((val, j) => {
                      const isCorrect = i === j;
                      const maxVal = Math.max(...confMatrix.flat());
                      const intensity = maxVal ? val / maxVal : 0;
                      return (
                        <td key={j} style={{
                          padding: '8px 12px', textAlign: 'center',
                          background: isCorrect
                            ? `rgba(255,255,255,${0.06 + intensity * 0.2})`
                            : val > 0 ? `rgba(229,62,62,${0.03 + intensity * 0.15})` : 'transparent',
                          color: isCorrect ? 'var(--accent-cyan)' : val > 0 ? '#fc8181' : 'var(--text-muted)',
                          fontWeight: isCorrect ? 600 : 400,
                        }}>
                          {val}
                        </td>
                      );
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
      {/* ── Live Confusion Matrix (Real-Time from DB) ── */}
      {live && live.total_events > 0 && (
        <div className="card" style={{ marginTop: 24 }}>
          <div className="section-header flex-between">
            <div className="section-title">Live Detection Matrix — Real-Time</div>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', letterSpacing: '0.08em' }}>
              {live.total_events.toLocaleString()} EVENTS ANALYZED
            </span>
          </div>

          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', marginBottom: 16, lineHeight: 1.8, padding: '0 0 14px', borderBottom: '1px solid var(--border-dim)' }}>
            <span style={{ color: '#63b3ed', fontWeight: 600 }}>Live data:</span> This matrix updates in real-time from actual events flowing through TrustFlow. The training matrix above is static from model evaluation — this one reflects what's happening <strong>right now</strong>.
          </div>

          {/* Summary KPIs */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 1fr', gap: 14, marginBottom: 20 }}>
            <div className="metric-card">
              <div className="metric-label">Normal Events</div>
              <div className="metric-value" style={{ color: 'var(--accent-cyan)' }}>{live.normal_count.toLocaleString()}</div>
              <div className="metric-delta">{live.total_events > 0 ? Math.round(live.normal_count / live.total_events * 100) : 0}% of total</div>
            </div>
            <div className="metric-card">
              <div className="metric-label">Threats Detected</div>
              <div className="metric-value" style={{ color: '#e53e3e' }}>{live.attack_count.toLocaleString()}</div>
              <div className="metric-delta">{live.total_events > 0 ? Math.round(live.attack_count / live.total_events * 100) : 0}% of total</div>
            </div>
            <div className="metric-card">
              <div className="metric-label">Analyst Confirmed</div>
              <div className="metric-value" style={{ color: '#48bb78' }}>{live.analyst_confirmed}</div>
              <div className="metric-delta">{live.analyst_reviewed} reviewed total</div>
            </div>
            <div className="metric-card">
              <div className="metric-label">False Positives</div>
              <div className="metric-value" style={{ color: live.live_fp_rate > 15 ? '#e53e3e' : '#e6a817' }}>{live.analyst_false_positive}</div>
              <div className="metric-delta">FP rate: {live.live_fp_rate}%</div>
            </div>
          </div>

          {/* Live class distribution */}
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-muted)', letterSpacing: '0.15em', textTransform: 'uppercase', marginBottom: 10 }}>
            Attack Type Distribution (Live)
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {live.classes.map(cls => (
              <div key={cls.class} style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                <div style={{ width: 120, fontFamily: 'var(--font-mono)', fontSize: 11, color: cls.class === 'normal' ? 'var(--accent-cyan)' : 'var(--text-secondary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {cls.class}
                </div>
                <div style={{ flex: 1, height: 6, background: 'var(--bg-elevated)', borderRadius: 3, overflow: 'hidden' }}>
                  <div style={{
                    width: `${cls.pct}%`, height: '100%', borderRadius: 3,
                    background: cls.class === 'normal' ? 'var(--accent-cyan)' : cls.pct > 20 ? '#e53e3e' : cls.pct > 10 ? '#ed8936' : '#e6a817',
                    transition: 'width 0.5s ease',
                  }} />
                </div>
                <div style={{ width: 60, fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-secondary)', textAlign: 'right' }}>
                  {cls.count} <span style={{ color: 'var(--text-muted)', fontSize: 9 }}>({cls.pct}%)</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* SHAP Feature Importance */}
      {shap && shap.features && shap.features.length > 0 && (
        <div className="card" style={{ marginTop: 24 }}>
          <div className="section-header flex-between">
            <div className="section-title">Explainable AI — Feature Importance</div>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', letterSpacing: '0.08em' }}>
              SOURCE: {(shap.source || 'static').toUpperCase()}
            </span>
          </div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-muted)', marginBottom: 16, lineHeight: 1.8 }}>
            <span style={{ color: '#63b3ed', fontWeight: 600 }}>What is this?</span> SHAP (SHapley Additive exPlanations) shows <strong>which features matter most</strong> when the AI makes a decision.
            Instead of a "black box" that just says "attack detected," this chart explains <em>why</em> the model thinks so.<br/>
            <span style={{ color: '#ffffff' }}>Longer bars = more important</span>. For example, if "Login Failure" is the top bar, it means failed login attempts are the strongest signal the model uses to detect attacks.
          </div>
          <ResponsiveContainer width="100%" height={280}>
            <BarChart
              data={shap.features.slice(0, 10).map(f => ({ name: f.feature, value: Math.round(f.importance * 1000) / 10 }))}
              layout="vertical"
              margin={{ top: 0, right: 20, left: 10, bottom: 0 }}
            >
              <XAxis type="number" tick={{ fill: 'var(--text-muted)', fontSize: 9 }} axisLine={false} tickLine={false} />
              <YAxis type="category" dataKey="name" tick={{ fill: 'var(--text-secondary)', fontSize: 11, fontFamily: 'var(--font-mono)' }} axisLine={false} tickLine={false} width={150} />
              <Tooltip
                formatter={(v) => [`${v}`, 'Importance']}
                contentStyle={{ background: 'var(--bg-elevated)', border: '1px solid var(--border-mid)', borderRadius: 6, fontFamily: 'var(--font-mono)', fontSize: 11 }}
              />
              <Bar dataKey="value" radius={[0, 3, 3, 0]}>
                {shap.features.slice(0, 10).map((f, i) => (
                  <Cell key={i} fill={[
                    '#e53e3e', '#ff6b35', '#ed8936', '#e6a817', '#d4ff00',
                    '#ffffff', '#63b3ed', '#b794f4', '#ffffff', '#e6a817'
                  ][i % 10]} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}

      {/* ── Dataset & Model Provenance ── */}
      <div className="card" style={{ marginTop: 24, borderColor: 'rgba(74,158,255,0.2)' }}>
        <div className="section-header flex-between">
          <div className="section-title">📊 Dataset & Model Provenance</div>
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)' }}>ENTERPRISE READINESS</span>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 16 }}>
          {[
            {
              title: 'Current Dataset',
              color: '#ffffff',
              icon: '◉',
              lines: [
                'Synthetic labeled dataset',
                '15 attack class labels (OWASP Top 10)',
                'Balanced class distribution',
                'Generated via train_ml_engine.py',
              ],
            },
            {
              title: 'Production Datasets',
              color: '#63b3ed',
              icon: '◈',
              lines: [
                'CIC-IDS2017 (University of NB)',
                'UNSW-NB15 (ADFA/UNSW)',
                'KDD Cup 99 (UCI)',
                'Drop-in compatible with pipeline',
              ],
            },
            {
              title: 'Future Architecture',
              color: '#b794f4',
              icon: '◆',
              lines: [
                'Neo4j for attack graph scalability',
                'Real-time stream via Kafka',
                'PostgreSQL for event storage',
                'MITRE ATT&CK STIX feeds',
              ],
            },
          ].map(({ title, color, icon, lines }) => (
            <div key={title} style={{ background: 'var(--bg-elevated)', borderRadius: 8, padding: '14px 16px', borderLeft: `3px solid ${color}` }}>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color, letterSpacing: '0.08em', marginBottom: 10 }}>
                {icon} {title}
              </div>
              <ul style={{ listStyle: 'none', padding: 0, display: 'flex', flexDirection: 'column', gap: 5 }}>
                {lines.map(line => (
                  <li key={line} style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', display: 'flex', gap: 6 }}>
                    <span style={{ color }}>›</span> {line}
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
        <div style={{ marginTop: 14, padding: '10px 14px', background: 'rgba(74,158,255,0.05)', borderRadius: 6, border: '1px solid rgba(74,158,255,0.15)', fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-muted)' }}>
          💡 <span style={{ color: '#63b3ed' }}>Production note:</span> To train on a real-world dataset, replace the CSV in <span style={{ color: 'var(--accent-cyan)' }}>data/labeled_logs.csv</span> with CIC-IDS2017 or UNSW-NB15 data and re-run <span style={{ color: 'var(--accent-cyan)' }}>python utils/train_ml_engine.py</span>.
        </div>
      </div>

      {/* Adversarial Robustness Testing */}
      <div className="card" style={{ marginTop: 24, borderColor: adversarial?.verdict === 'VULNERABLE' ? 'rgba(229,62,62,0.3)' : adversarial?.verdict === 'ROBUST' ? 'rgba(255,255,255,0.2)' : 'rgba(255,184,0,0.2)' }}>
        <div className="section-header flex-between">
          <div className="section-title">Adversarial Robustness Testing</div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            {adversarial?.verdict && (
              <span style={{
                padding: '4px 12px', borderRadius: 4, fontFamily: 'var(--font-mono)', fontSize: 11,
                background: adversarial.verdict === 'ROBUST' ? 'rgba(255,255,255,0.1)' : adversarial.verdict === 'MODERATE' ? 'rgba(255,184,0,0.1)' : 'rgba(229,62,62,0.1)',
                color: adversarial.verdict === 'ROBUST' ? '#ffffff' : adversarial.verdict === 'MODERATE' ? '#e6a817' : '#e53e3e',
                border: `1px solid ${adversarial.verdict === 'ROBUST' ? 'rgba(255,255,255,0.3)' : adversarial.verdict === 'MODERATE' ? 'rgba(255,184,0,0.3)' : 'rgba(229,62,62,0.3)'}`,
              }}>
                {adversarial.verdict}
              </span>
            )}
            <button className="btn btn-primary" style={{ fontSize: 10, padding: '6px 14px' }}
              disabled={advLoading}
              onClick={async () => {
                setAdvLoading(true);
                setAdvStatus(null);
                try {
                  const r = await runAdversarialTests();
                  setAdversarial(r);
                  setAdvStatus({ type: 'success', msg: `Tests completed — ${r.overall_detection_rate ?? 100}% detection rate` });
                } catch (e) {
                  setAdvStatus({ type: 'error', msg: e?.response?.data?.detail || 'Test failed — check server logs' });
                }
                setAdvLoading(false);
                setTimeout(() => setAdvStatus(null), 6000);
              }}>
              {advLoading ? 'TESTING...' : 'RUN TESTS'}
            </button>
            {advStatus && (
              <span style={{
                fontSize: 10, marginLeft: 10, padding: '4px 10px', borderRadius: 4,
                background: advStatus.type === 'success' ? 'rgba(72,187,120,0.15)' : 'rgba(229,62,62,0.15)',
                color: advStatus.type === 'success' ? '#48bb78' : '#e53e3e',
                border: `1px solid ${advStatus.type === 'success' ? 'rgba(72,187,120,0.3)' : 'rgba(229,62,62,0.3)'}`,
              }}>{advStatus.msg}</span>
            )}
          </div>
        </div>

        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', marginBottom: 14, lineHeight: 1.8 }}>
          <span style={{ color: '#63b3ed', fontWeight: 600 }}>What is this?</span> We attack our <strong>LightGBM threat-classification model</strong> (trained on 21 CIC-IDS2017 features across 15 attack classes) with 5 adversarial evasion techniques — slow brute force, mimicry, IP rotation, insider exfiltration, and encoded SQLi — to test if attackers can bypass detection.
          A <span style={{ color: '#ffffff' }}>ROBUST</span> verdict means the model catches attacks even when they're disguised. If the evasion rate is high, the model needs improvement.
        </div>

        {adversarial?.overall_detection_rate !== undefined && (
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 14, marginBottom: 16 }}>
            <div className="metric-card">
              <div className="metric-label">Detection Rate</div>
              <div className="metric-value" style={{ color: adversarial.overall_detection_rate >= 80 ? '#ffffff' : '#e6a817' }}>
                {adversarial.overall_detection_rate}%
              </div>
            </div>
            <div className="metric-card">
              <div className="metric-label">Evasion Rate</div>
              <div className="metric-value" style={{ color: adversarial.overall_evasion_rate > 20 ? '#e53e3e' : '#ffffff' }}>
                {adversarial.overall_evasion_rate}%
              </div>
            </div>
            <div className="metric-card">
              <div className="metric-label">Samples Tested</div>
              <div className="metric-value cyan">{adversarial.total_adversarial_samples}</div>
            </div>
          </div>
        )}

        {adversarial?.tests?.length > 0 && (<>
          <table className="data-table">
            <thead>
              <tr>
                <th>Evasion Technique</th>
                <th>MITRE ID</th>
                <th>Method</th>
                <th>Samples</th>
                <th>Detected</th>
                <th>Rate</th>
              </tr>
            </thead>
            <tbody>
              {adversarial.tests.map((t, i) => (
                <tr key={i}>
                  <td style={{ color: 'var(--text-primary)' }}>{t.name}</td>
                  <td style={{ color: '#63b3ed', fontFamily: 'var(--font-mono)', fontSize: 10 }}>{t.technique?.split(' - ')[0]}</td>
                  <td style={{ color: 'var(--text-muted)', fontSize: 11 }}>{t.evasion_method}</td>
                  <td>{t.total_samples}</td>
                  <td style={{ color: t.detected === t.total_samples ? '#ffffff' : '#e6a817' }}>{t.detected}</td>
                  <td style={{
                    color: t.detection_rate >= 80 ? '#ffffff' : t.detection_rate >= 50 ? '#e6a817' : '#e53e3e',
                    fontFamily: 'var(--font-mono)',
                  }}>
                    {t.detection_rate}%
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {adversarial.timestamp && (
            <div style={{ marginTop: 10, fontSize: 10, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
              Last tested: {new Date(adversarial.timestamp).toLocaleString()}
            </div>
          )}
        </>)}

        {(!adversarial || !adversarial.tests?.length) && (
          <div className="p-empty" style={{ padding: 30 }}>
            Click "RUN TESTS" to evaluate model robustness against adversarial evasion techniques.
          </div>
        )}
      </div>
    </div>
  );
}

