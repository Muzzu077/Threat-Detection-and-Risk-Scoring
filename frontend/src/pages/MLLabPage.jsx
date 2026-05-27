import { useEffect, useState } from 'react';
import {
  fetchEnsembleMetrics, trainEnsemble,
  fetchZeroDayClusters,
  fetchSequenceAnomaly, trainSequenceModel,
} from '../api/client';

const btnPrimary = {
  fontFamily: 'var(--font-mono)', fontSize: 11,
  padding: '8px 16px', borderRadius: 'var(--radius-sm)', border: 'none', cursor: 'pointer',
  background: 'var(--bg-glass-heavy)', color: 'var(--text-primary)',
  letterSpacing: '0.08em', textTransform: 'uppercase',
  outline: '1px solid var(--border-mid)',
};

function Section({ title, subtitle, action, children }) {
  return (
    <div style={{
      background: 'var(--bg-card)', backdropFilter: 'blur(16px)', border: '1px solid var(--border-light)',
      borderRadius: 'var(--radius-lg)', padding: 22, marginBottom: 20, boxShadow: 'var(--shadow-sm)'
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 14 }}>
        <div>
          <div style={{ fontFamily: 'var(--font-display)', fontSize: 16, color: 'var(--text-primary)', letterSpacing: 1.5 }}>
            {title}
          </div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-muted)', letterSpacing: '0.18em', marginTop: 4, textTransform: 'uppercase' }}>
            {subtitle}
          </div>
        </div>
        {action}
      </div>
      {children}
    </div>
  );
}

function ModelStatRow({ label, accuracy, f1, members }) {
  const accColor = accuracy >= 90 ? 'var(--accent-green)' : accuracy >= 75 ? 'var(--accent-orange)' : 'var(--accent-red)';
  return (
    <div style={{
      display: 'grid', gridTemplateColumns: '1fr 100px 100px',
      padding: '10px 0', borderBottom: '1px solid var(--border-dim)',
      alignItems: 'center', gap: 16,
    }}>
      <div>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-primary)', letterSpacing: '0.05em' }}>
          {label}
        </div>
        {members && (
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-muted)', letterSpacing: '0.1em', marginTop: 2 }}>
            {members.join(' + ')} · averaged probabilities
          </div>
        )}
      </div>
      <div style={{ fontFamily: 'var(--font-display)', fontSize: 18, color: accColor, textAlign: 'right' }}>
        {accuracy != null ? `${accuracy}%` : '—'}
      </div>
      <div style={{ fontFamily: 'var(--font-display)', fontSize: 18, color: 'var(--accent-blue)', textAlign: 'right' }}>
        {f1 != null ? `${f1}%` : '—'}
      </div>
    </div>
  );
}

function EnsembleSection() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [training, setTraining] = useState(false);
  const [err, setErr] = useState('');

  const load = async () => {
    setLoading(true);
    try {
      const d = await fetchEnsembleMetrics();
      setData(d);
    } catch { setErr('FAILED TO LOAD METRICS'); }
    setLoading(false);
  };
  useEffect(() => { load(); }, []);

  const handleTrain = async () => {
    setTraining(true); setErr('');
    try {
      await trainEnsemble();
      await load();
    } catch (e) {
      setErr(e.response?.data?.detail || 'TRAINING FAILED');
    }
    setTraining(false);
  };

  const per = data?.per_model || {};
  return (
    <Section
      title="ENSEMBLE CLASSIFIER"
      subtitle="LightGBM + XGBoost · averaged probabilities"
      action={<button onClick={handleTrain} disabled={training} style={btnPrimary} className="btn btn-primary">{training ? 'TRAINING...' : 'TRAIN XGB'}</button>}
    >
      {err && <div style={errStyle}>{err}</div>}
      {loading ? <Loading /> : (
        <>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 100px 100px',
                        padding: '6px 0', borderBottom: '1px solid var(--border-light)',
                        fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-muted)',
                        letterSpacing: '0.18em', textTransform: 'uppercase', gap: 16 }}>
            <span>Model</span>
            <span style={{ textAlign: 'right' }}>Accuracy</span>
            <span style={{ textAlign: 'right' }}>F1</span>
          </div>
          <ModelStatRow label="LightGBM"             accuracy={per.lgbm?.accuracy}     f1={per.lgbm?.f1} />
          <ModelStatRow label="XGBoost"              accuracy={per.xgb?.accuracy}      f1={per.xgb?.f1} />
          <ModelStatRow label="Ensemble (averaged)"  accuracy={per.ensemble?.accuracy} f1={per.ensemble?.f1} members={per.ensemble?.members} />
          {data?.test_set_size && (
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-faint)', marginTop: 14, letterSpacing: '0.12em' }}>
              evaluated on {data.test_set_size} held-out samples · {data.evaluated_at && new Date(data.evaluated_at).toLocaleString('en-US')}
            </div>
          )}
        </>
      )}
    </Section>
  );
}

function ZeroDaySection() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const load = async () => { try { setData(await fetchZeroDayClusters()); } finally { setLoading(false); } };
  useEffect(() => { load(); }, []);

  return (
    <Section
      title="ZERO-DAY CLUSTERS"
      subtitle={`DBSCAN unsupervised · ${data?.total_analysed ?? 0} candidates analysed`}
      action={<button onClick={() => { setLoading(true); load(); }} style={btnPrimary} className="btn btn-ghost">REFRESH</button>}
    >
      {loading ? <Loading /> :
        !data?.clusters?.length ? <Empty msg="No suspicious clusters surfaced from current event volume" /> : (
          <table className="data-table" style={{ marginTop: 4 }}>
            <thead><tr>{['CLUSTER', 'SIZE', 'NOVELTY', 'MEAN RISK', 'COMMON RESOURCE', 'IPs/USERS'].map(h => <th key={h}>{h}</th>)}</tr></thead>
            <tbody>
              {data.clusters.slice(0, 10).map(c => (
                <tr key={c.cluster_id}>
                  <td style={mono(11, 'var(--text-primary)')}>#{c.cluster_id}</td>
                  <td style={mono(12, 'var(--accent-blue)')}>{c.size}</td>
                  <td style={mono(12, 'var(--accent-orange)')}>{c.novelty_score}</td>
                  <td style={mono(12, c.mean_risk >= 60 ? 'var(--accent-red)' : c.mean_risk >= 30 ? 'var(--accent-orange)' : 'var(--accent-green)')}>{c.mean_risk}</td>
                  <td style={{ ...mono(10, 'var(--text-secondary)'), maxWidth: 320, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{c.common_resource}</td>
                  <td style={mono(10, 'var(--text-muted)')}>{c.unique_ips}/{c.unique_users}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )
      }
      {data?.isolated_outliers > 0 && (
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', marginTop: 14, letterSpacing: '0.12em' }}>
          + {data.isolated_outliers} isolated outliers (single-event anomalies, not yet a cluster)
        </div>
      )}
    </Section>
  );
}

function SequenceSection() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [training, setTraining] = useState(false);
  const [trainResult, setTrainResult] = useState(null);

  const load = async () => { try { setData(await fetchSequenceAnomaly(10)); } finally { setLoading(false); } };
  useEffect(() => { load(); }, []);

  const handleTrain = async () => {
    setTraining(true); setTrainResult(null);
    try {
      const r = await trainSequenceModel(5);
      setTrainResult(r);
      await load();
    } catch (e) { setTrainResult({ error: e.response?.data?.detail || 'failed' }); }
    setTraining(false);
  };

  const isModel = data?.method === 'transformer';
  return (
    <Section
      title="SEQUENCE ANOMALY"
      subtitle={`Transformer encoder · ${data?.total_users ?? 0} sessions · method: ${data?.method ?? '—'}`}
      action={<button onClick={handleTrain} disabled={training} style={btnPrimary} className="btn btn-primary">{training ? 'TRAINING...' : 'TRAIN MODEL'}</button>}
    >
      {!isModel && data && (
        <div style={{
          fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--accent-orange)',
          padding: '8px 12px', marginBottom: 14, background: 'rgba(230,168,23,0.06)',
          border: '1px solid rgba(230,168,23,0.2)', borderRadius: 'var(--radius-sm)', letterSpacing: '0.06em',
        }}>
          ⚠ Running on heuristic fallback. Click TRAIN MODEL to fit the transformer on platform-wide data.
        </div>
      )}
      {trainResult && (
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: trainResult.error ? 'var(--accent-red)' : 'var(--accent-green)', marginBottom: 12, letterSpacing: '0.06em' }}>
          {trainResult.error ? `✗ ${trainResult.error}` :
            `✓ Trained on ${trainResult.training_windows} windows · vocab ${trainResult.vocab_size} · final loss ${trainResult.final_loss}`}
        </div>
      )}
      {loading ? <Loading /> :
        !data?.sessions?.length ? <Empty msg="No sessions long enough to score yet (need 3+ events per user)" /> : (
          <table className="data-table" style={{ marginTop: 4 }}>
            <thead><tr>{['USER', 'SESSION LENGTH', 'ANOMALY', 'SAMPLE PATTERN'].map(h => <th key={h}>{h}</th>)}</tr></thead>
            <tbody>
              {data.sessions.map(s => {
                const score = s.anomaly_score;
                const color = score >= 0.7 ? 'var(--accent-red)' : score >= 0.4 ? 'var(--accent-orange)' : 'var(--accent-green)';
                return (
                  <tr key={s.user}>
                    <td style={mono(12, 'var(--text-primary)')}>{s.user}</td>
                    <td style={mono(12, 'var(--accent-blue)')}>{s.length}</td>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <div style={{ width: 80, height: 4, background: 'var(--border-dim)', borderRadius: 2, overflow: 'hidden' }}>
                          <div style={{ width: `${score * 100}%`, height: '100%', background: color, transition: 'width 0.3s' }} />
                        </div>
                        <span style={{ ...mono(11, color), minWidth: 36 }}>{score.toFixed(2)}</span>
                      </div>
                    </td>
                    <td style={{ ...mono(9, 'var(--text-secondary)'), maxWidth: 360, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {s.sample_tokens.join(' → ')}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )
      }
    </Section>
  );
}

const errStyle = {
  fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--accent-red)',
  padding: '8px 12px', marginBottom: 12,
  background: 'rgba(185,28,28,0.08)', border: '1px solid rgba(185,28,28,0.22)', borderRadius: 'var(--radius-sm)',
};
const mono = (sz, c) => ({ fontFamily: 'var(--font-mono)', fontSize: sz, color: c });
const Loading = () => <div style={{ padding: 30, textAlign: 'center', fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-muted)' }}>Loading...</div>;
const Empty = ({ msg }) => <div style={{ padding: 30, textAlign: 'center', fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-muted)' }}>{msg}</div>;

export default function MLLabPage() {
  return (
    <div className="page-enter">
      <div style={{ marginBottom: 28 }}>
        <div style={{ fontFamily: 'var(--font-display)', fontSize: 22, color: 'var(--text-primary)', letterSpacing: 2 }}>
          ML LAB
        </div>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', letterSpacing: 4, textTransform: 'uppercase', marginTop: 4 }}>
          Phase 2 · ensemble · zero-day · sequence anomaly
        </div>
      </div>
      <EnsembleSection />
      <ZeroDaySection />
      <SequenceSection />
    </div>
  );
}
