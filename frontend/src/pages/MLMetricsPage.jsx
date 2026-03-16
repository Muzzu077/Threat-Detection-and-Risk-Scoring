import { useEffect, useState } from 'react';
import { fetchMLMetrics, fetchExplainability } from '../api/client';
import { RadarChart, Radar, PolarGrid, PolarAngleAxis, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, Cell } from 'recharts';

const METRIC_COLOR = { Accuracy: '#00e5b0', Precision: '#4a9eff', Recall: '#ffb800', 'F1 Score': '#ff8c00' };

export default function MLMetricsPage() {
  const [metrics, setMetrics] = useState(null);
  const [shap, setShap] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([fetchMLMetrics(), fetchExplainability()]).then(([m, s]) => {
      setMetrics(m);
      setShap(s);
      setLoading(false);
    }).catch(() => setLoading(false));
  }, []);

  if (loading) return <div className="loading"><div className="spinner"/><div className="loading-text">Loading ML metrics...</div></div>;

  if (!metrics || metrics.message) return (
    <div className="fade-in">
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

  // Confusion matrix
  const confMatrix = metrics.confusion_matrix || [];

  return (
    <div className="fade-in">
      <div className="flex-between mb-24">
        <div>
          <div className="page-title">◎ ML METRICS</div>
          <div className="page-subtitle">{metrics.model_type} Classifier — Performance Analysis</div>
        </div>
        <div style={{ padding: '6px 14px', background: 'rgba(0,255,200,0.08)', border: '1px solid var(--border-mid)', borderRadius: 5, fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--accent-cyan)' }}>
          {metrics.model_type?.toUpperCase()}
        </div>
      </div>

      {/* Summary KPIs */}
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
          <ResponsiveContainer width="100%" height={240}>
            <RadarChart data={radarData}>
              <PolarGrid stroke="rgba(0,255,200,0.1)" />
              <PolarAngleAxis dataKey="metric" tick={{ fill: 'var(--text-muted)', fontSize: 11, fontFamily: 'var(--font-mono)' }} />
              <Radar name="Score" dataKey="value" stroke="var(--accent-cyan)" fill="var(--accent-cyan)" fillOpacity={0.12} />
            </RadarChart>
          </ResponsiveContainer>
        </div>

        {/* Per-class F1 chart */}
        <div className="chart-container">
          <div className="chart-title">F1-Score by Attack Class</div>
          <ResponsiveContainer width="100%" height={240}>
            <BarChart data={classData} layout="vertical" margin={{ top: 0, right: 0, left: 10, bottom: 0 }}>
              <XAxis type="number" domain={[0, 100]} tick={{ fill: 'var(--text-muted)', fontSize: 9 }} axisLine={false} tickLine={false} />
              <YAxis type="category" dataKey="name" tick={{ fill: 'var(--text-secondary)', fontSize: 10, fontFamily: 'var(--font-mono)' }} axisLine={false} tickLine={false} width={100} />
              <Tooltip formatter={(v) => `${v}%`} contentStyle={{ background: 'var(--bg-elevated)', border: '1px solid var(--border-mid)', borderRadius: 6, fontFamily: 'var(--font-mono)', fontSize: 11 }} />
              <Bar dataKey="f1" radius={[0, 2, 2, 0]} name="F1">
                {classData.map((_, i) => <Cell key={i} fill={['#f03250','#ff8c00','#ffb800','#00e5b0','#4a9eff'][i % 5]} />)}
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
                <td style={{ color: '#4a9eff' }}>{cls.precision}%</td>
                <td style={{ color: '#ffb800' }}>{cls.recall}%</td>
                <td style={{ color: '#00e5b0' }}>{cls.f1}%</td>
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
                            ? `rgba(0,255,200,${0.06 + intensity * 0.2})`
                            : val > 0 ? `rgba(255,45,45,${0.03 + intensity * 0.15})` : 'transparent',
                          color: isCorrect ? 'var(--accent-cyan)' : val > 0 ? '#ff6b6b' : 'var(--text-muted)',
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
      {/* SHAP Feature Importance */}
      {shap && shap.features && shap.features.length > 0 && (
        <div className="card" style={{ marginTop: 24 }}>
          <div className="section-header flex-between">
            <div className="section-title">Explainable AI — Feature Importance</div>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', letterSpacing: '0.08em' }}>
              SOURCE: {(shap.source || 'static').toUpperCase()}
            </span>
          </div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-muted)', marginBottom: 16 }}>
            Top factors driving the ML threat detection model — based on
            {shap.source === 'shap' ? ' SHAP TreeExplainer values' : ' model feature importances'}.
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
                    '#f03250', '#ff6b35', '#ff8c00', '#ffb800', '#d4ff00',
                    '#00e5b0', '#4a9eff', '#a855f7', '#00e5b0', '#ffb800'
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
              color: '#00e5b0',
              icon: '◉',
              lines: [
                'Synthetic labeled dataset',
                '5 attack class labels',
                'Balanced class distribution',
                'Generated via train_ml_engine.py',
              ],
            },
            {
              title: 'Production Datasets',
              color: '#4a9eff',
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
              color: '#a855f7',
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
          💡 <span style={{ color: '#4a9eff' }}>Production note:</span> To train on a real-world dataset, replace the CSV in <span style={{ color: 'var(--accent-cyan)' }}>data/labeled_logs.csv</span> with CIC-IDS2017 or UNSW-NB15 data and re-run <span style={{ color: 'var(--accent-cyan)' }}>python utils/train_ml_engine.py</span>.
        </div>
      </div>
    </div>
  );
}

