import { useEffect, useState } from 'react';
import { fetchPrediction } from '../api/client';

const LEVEL_COLORS = {
  critical: '#f03250',
  high: '#ff8c00',
  medium: '#ffb800',
  low: '#00e5b0',
  monitoring: '#4a9eff',
};

const LEVEL_GLOW = {
  critical: 'var(--glow-red)',
  high: '0 0 20px rgba(255,140,0,0.3)',
  medium: 'var(--glow-amber)',
  low: 'var(--glow-cyan)',
  monitoring: '0 0 20px rgba(74,158,255,0.2)',
};

export default function PredictionWidget() {
  const [prediction, setPrediction] = useState(null);
  const [loading, setLoading] = useState(true);

  const load = async () => {
    try {
      const data = await fetchPrediction();
      setPrediction(data);
    } catch {}
    setLoading(false);
  };

  useEffect(() => {
    load();
    const interval = setInterval(load, 15000);
    return () => clearInterval(interval);
  }, []);

  if (loading) return (
    <div className="card" style={{ minHeight: 140 }}>
      <div className="loading" style={{ padding: 20 }}>
        <div className="spinner" style={{ width: 20, height: 20 }} />
        <div className="loading-text">Analyzing patterns...</div>
      </div>
    </div>
  );

  if (!prediction) return null;

  const level = prediction.threat_level || 'monitoring';
  const color = LEVEL_COLORS[level] || '#4a9eff';
  const glow = LEVEL_GLOW[level] || '';
  const conf = prediction.confidence || 0;

  return (
    <div className="card" style={{
      borderColor: `${color}44`,
      boxShadow: prediction.pattern_detected ? glow : 'none',
      transition: 'all 0.5s ease',
    }}>
      {/* Header */}
      <div className="flex-between mb-16">
        <div className="section-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ animation: prediction.pattern_detected ? 'pulse-live 1.5s infinite' : 'none' }}>⚡</span>
          THREAT PREDICTION
          <span style={{ fontSize: 9, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', letterSpacing: '0.1em' }}>
            PATTERN ENGINE
          </span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span className={`badge badge-${level === 'monitoring' ? 'normal' : level}`} style={{ borderColor: `${color}60` }}>
            {level.toUpperCase()}
          </span>
          <button className="btn btn-ghost" style={{ fontSize: 9, padding: '4px 8px' }} onClick={load}>↺</button>
        </div>
      </div>

      {/* Prediction text */}
      <div style={{
        fontFamily: 'var(--font-display)',
        fontSize: 14,
        color,
        textShadow: prediction.pattern_detected ? `0 0 12px ${color}60` : 'none',
        marginBottom: 8,
        lineHeight: 1.4,
      }}>
        {prediction.prediction}
      </div>

      {/* Description */}
      <div style={{
        fontFamily: 'var(--font-body)',
        fontSize: 12,
        color: 'var(--text-secondary)',
        lineHeight: 1.6,
        marginBottom: 16,
      }}>
        {prediction.description}
      </div>

      {/* Metrics row */}
      <div style={{ display: 'flex', gap: 20, marginBottom: 12 }}>
        {/* Confidence gauge */}
        <div style={{ flex: 1 }}>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-muted)', marginBottom: 4, letterSpacing: '0.1em' }}>
            CONFIDENCE
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <div style={{ flex: 1, height: 5, background: 'var(--bg-elevated)', borderRadius: 3, overflow: 'hidden' }}>
              <div style={{
                width: `${conf}%`,
                height: '100%',
                background: color,
                borderRadius: 3,
                transition: 'width 1s ease',
                boxShadow: `0 0 6px ${color}80`,
              }} />
            </div>
            <span style={{ fontFamily: 'var(--font-display)', fontSize: 16, color, minWidth: 36 }}>
              {conf}%
            </span>
          </div>
        </div>

        {/* Velocity */}
        <div style={{ minWidth: 80 }}>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-muted)', marginBottom: 4, letterSpacing: '0.1em' }}>
            VELOCITY
          </div>
          <span style={{ fontFamily: 'var(--font-display)', fontSize: 16, color: prediction.velocity > 3 ? '#ff8c00' : 'var(--text-secondary)' }}>
            {prediction.velocity}
          </span>
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-muted)', marginLeft: 2 }}>ev/min</span>
        </div>
      </div>

      {/* MITRE next technique */}
      {prediction.mitre_next && (
        <div style={{
          background: 'rgba(0,255,200,0.05)', border: '1px solid var(--border-dim)',
          borderRadius: 5, padding: '8px 12px', marginBottom: 10,
          fontFamily: 'var(--font-mono)', fontSize: 11,
        }}>
          <span style={{ color: 'var(--text-muted)', fontSize: 9, letterSpacing: '0.1em' }}>MITRE PREDICTION: </span>
          <span style={{ color: 'var(--accent-cyan)' }}>{prediction.mitre_next}</span>
        </div>
      )}

      {/* Recommended action */}
      {prediction.recommended_action && (
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', lineHeight: 1.5 }}>
          ▶ {prediction.recommended_action}
        </div>
      )}

      {/* Pattern label */}
      {prediction.pattern && (
        <div style={{ marginTop: 10, display: 'flex', alignItems: 'center', gap: 6 }}>
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-muted)', letterSpacing: '0.1em' }}>PATTERN:</span>
          <span className="badge badge-medium" style={{ fontSize: 9 }}>{prediction.pattern.replace(/_/g, ' ')}</span>
        </div>
      )}
    </div>
  );
}
