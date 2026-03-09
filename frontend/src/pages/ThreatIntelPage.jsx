import { useState } from 'react';
import { fetchThreatIntel } from '../api/client';

const QUICK_IPS = ['45.33.22.11', '182.21.4.9', '185.220.101.3', '8.8.8.8', '1.1.1.1'];

function ScoreGauge({ score }) {
  const color = score >= 75 ? '#f03250' : score >= 40 ? '#ff8c00' : score >= 15 ? '#ffb800' : '#00e5b0';
  const label = score >= 75 ? 'CRITICAL THREAT' : score >= 40 ? 'HIGH RISK' : score >= 15 ? 'MODERATE' : 'CLEAN';
  return (
    <div style={{ marginBottom: 24 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', marginBottom: 10 }}>
        <div style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 9, letterSpacing: 3, color: '#2e5570', textTransform: 'uppercase' }}>Abuse Confidence Score</div>
        <div style={{ display: 'flex', alignItems: 'baseline', gap: 8 }}>
          <span style={{ fontFamily: 'Syne Mono, monospace', fontSize: 36, color, textShadow: `0 0 20px ${color}40` }}>{score}</span>
          <span style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 14, color: '#2e5570' }}>%</span>
        </div>
      </div>
      <div style={{ height: 8, background: 'rgba(255,255,255,0.05)', borderRadius: 4, overflow: 'hidden', position: 'relative' }}>
        <div style={{ position: 'absolute', inset: 0, background: 'repeating-linear-gradient(90deg, transparent, transparent 9px, rgba(255,255,255,0.02) 9px, rgba(255,255,255,0.02) 10px)' }} />
        <div style={{ width: `${score}%`, height: '100%', background: `linear-gradient(90deg, #00e5b0, ${color})`, borderRadius: 4, transition: 'width 1.2s ease', boxShadow: `0 0 12px ${color}60` }} />
      </div>
      <div style={{ marginTop: 8, display: 'flex', justifyContent: 'space-between', fontFamily: 'IBM Plex Mono, monospace', fontSize: 10 }}>
        <span style={{ color: '#2e5570' }}>Safe</span>
        <span style={{ color, textShadow: `0 0 8px ${color}` }}>▲ {label}</span>
        <span style={{ color: '#2e5570' }}>Malicious</span>
      </div>
    </div>
  );
}

export default function ThreatIntelPage() {
  const [ip, setIp] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleCheck = async (e) => {
    e.preventDefault();
    if (!ip.trim()) return;
    setLoading(true);
    setError('');
    setResult(null);
    try {
      const data = await fetchThreatIntel(ip.trim());
      setResult(data);
    } catch {
      setError('Connection failed. Ensure FastAPI backend is running and AbuseIPDB key is set in .env');
    }
    setLoading(false);
  };

  const scoreColor = result ? (result.abuse_score >= 75 ? '#f03250' : result.abuse_score >= 40 ? '#ff8c00' : result.abuse_score >= 15 ? '#ffb800' : '#00e5b0') : '#00e5b0';

  return (
    <div className="fade-in">

      {/* Header */}
      <div style={{ marginBottom: 28 }}>
        <div style={{ fontFamily: 'Syne Mono, monospace', fontSize: 22, color: '#00e5b0', textShadow: '0 0 24px rgba(0,255,200,0.35)', letterSpacing: 2 }}>
          ◉ THREAT INTELLIGENCE
        </div>
        <div style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 10, color: '#2e5570', letterSpacing: 4, textTransform: 'uppercase', marginTop: 4 }}>
          IP Reputation Lookup — AbuseIPDB Integration
        </div>
      </div>

      {/* Notice */}
      <div style={{ padding: '12px 18px', borderRadius: 8, background: 'rgba(255,184,0,0.05)', border: '1px solid rgba(255,184,0,0.2)', marginBottom: 24, fontFamily: 'IBM Plex Mono, monospace', fontSize: 11, color: '#ffb800', display: 'flex', alignItems: 'center', gap: 10 }}>
        <span>⚠</span>
        <span>Set <span style={{ color: '#00e5b0' }}>ABUSEIPDB_API_KEY</span> in <span style={{ color: '#00e5b0' }}>.env</span> for live threat data. Free tier: 1,000 checks/day.</span>
      </div>

      {/* Lookup Form */}
      <div style={{ background: '#0c1520', border: '1px solid rgba(0,255,200,0.12)', borderRadius: 10, padding: 24, marginBottom: 24 }}>
        <div style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 10, color: '#2e5570', letterSpacing: 3, textTransform: 'uppercase', marginBottom: 16 }}>IP Lookup</div>
        <form onSubmit={handleCheck}>
          <div style={{ display: 'flex', gap: 10, marginBottom: 14, alignItems: 'center' }}>
            <div style={{ flex: 1, maxWidth: 380, position: 'relative' }}>
              <span style={{ position: 'absolute', left: 14, top: '50%', transform: 'translateY(-50%)', fontSize: 13, color: '#2e5570' }}>⌕</span>
              <input className="input" placeholder="Enter IP address (e.g. 45.33.22.11)"
                value={ip} onChange={e => setIp(e.target.value)} style={{ paddingLeft: 34, letterSpacing: 1 }} />
            </div>
            <button type="submit" className="btn btn-primary" disabled={loading} style={{ minWidth: 130 }}>
              {loading ? <><span className="spinner" style={{ width: 12, height: 12, borderWidth: 1.5 }} /> SCANNING...</> : '◉ ANALYZE IP'}
            </button>
          </div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
            <span style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 10, color: '#2e5570', letterSpacing: 2 }}>QUICK TEST:</span>
            {QUICK_IPS.map(testIp => (
              <button key={testIp} type="button" onClick={() => setIp(testIp)} style={{
                padding: '4px 12px', borderRadius: 4, fontFamily: 'IBM Plex Mono, monospace', fontSize: 10,
                background: ip === testIp ? 'rgba(0,255,200,0.1)' : 'transparent', color: ip === testIp ? '#00e5b0' : '#2e5570',
                border: `1px solid ${ip === testIp ? 'rgba(0,255,200,0.3)' : 'rgba(0,255,200,0.08)'}`, cursor: 'pointer', transition: 'all 0.2s', letterSpacing: 1
              }}>
                {testIp}
              </button>
            ))}
          </div>
        </form>
      </div>

      {error && (
        <div style={{ padding: '14px 18px', borderRadius: 8, background: 'rgba(255,45,45,0.07)', border: '1px solid rgba(255,45,45,0.3)', fontFamily: 'IBM Plex Mono, monospace', fontSize: 12, color: '#ff6b6b', marginBottom: 24 }}>
          ✘ {error}
        </div>
      )}

      {result && (
        <div className="fade-in" style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr', gap: 16 }}>

          {/* Main Result Panel */}
          <div style={{ background: '#0c1520', border: `1px solid ${result.is_suspicious ? 'rgba(255,45,45,0.3)' : 'rgba(0,255,200,0.2)'}`, borderRadius: 10, padding: 24, position: 'relative', overflow: 'hidden' }}>
            <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 3, background: `linear-gradient(90deg, transparent, ${scoreColor}, transparent)` }} />

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 20 }}>
              <div>
                <div style={{ fontFamily: 'Syne Mono, monospace', fontSize: 18, color: '#e8f4f8', letterSpacing: 1 }}>{result.ip}</div>
                <div style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 10, color: '#2e5570', letterSpacing: 2, marginTop: 4 }}>IPv4 ADDRESS</div>
              </div>
              <span style={{
                padding: '6px 14px', borderRadius: 4, fontFamily: 'IBM Plex Mono, monospace', fontSize: 11, letterSpacing: 2, textTransform: 'uppercase',
                background: result.is_suspicious ? 'rgba(255,45,45,0.15)' : 'rgba(0,255,200,0.08)',
                color: result.is_suspicious ? '#ff6b6b' : '#00e5b0',
                border: `1px solid ${result.is_suspicious ? 'rgba(255,45,45,0.3)' : 'rgba(0,255,200,0.2)'}`,
              }}>
                {result.is_suspicious ? '⚠ SUSPICIOUS' : '✓ CLEAN'}
              </span>
            </div>

            <ScoreGauge score={result.abuse_score || 0} />

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
              {[
                { label: 'Country', value: result.country || 'UNKNOWN', icon: '🌍' },
                { label: 'Total Reports', value: result.total_reports || 0, icon: '📋' },
                { label: 'Data Source', value: result.data_source || 'AbuseIPDB', icon: '◎' },
                { label: 'Classification', value: result.is_suspicious ? 'MALICIOUS' : 'BENIGN', icon: result.is_suspicious ? '⚠' : '✓' },
              ].map(({ label, value, icon }) => (
                <div key={label} style={{ padding: '12px 14px', background: '#101d2a', borderRadius: 8, border: '1px solid rgba(0,255,200,0.06)' }}>
                  <div style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 9, color: '#2e5570', letterSpacing: 2, textTransform: 'uppercase', marginBottom: 6 }}>{label}</div>
                  <div style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 13, color: '#e8f4f8' }}>{icon} {value}</div>
                </div>
              ))}
            </div>
          </div>

          {/* Threat Assessment Panel */}
          <div style={{ background: '#0c1520', border: '1px solid rgba(0,255,200,0.1)', borderRadius: 10, padding: 24 }}>
            <div style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 10, color: '#2e5570', letterSpacing: 3, textTransform: 'uppercase', marginBottom: 18 }}>Threat Assessment</div>

            {/* Recommendation box */}
            {result.abuse_score >= 75 && (
              <div style={{ padding: '16px 18px', borderRadius: 8, background: 'rgba(255,45,45,0.08)', border: '1px solid rgba(255,45,45,0.3)', marginBottom: 14 }}>
                <div style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 12, color: '#ff6b6b', marginBottom: 8 }}>🚨 HIGH CONFIDENCE THREAT</div>
                <div style={{ fontSize: 12, color: '#6e9ab5', lineHeight: 1.7 }}>Immediate blocking recommended. This IP shows {result.abuse_score}% abuse confidence with {result.total_reports} reports in the database.</div>
              </div>
            )}
            {result.abuse_score >= 15 && result.abuse_score < 75 && (
              <div style={{ padding: '16px 18px', borderRadius: 8, background: 'rgba(255,184,0,0.07)', border: '1px solid rgba(255,184,0,0.25)', marginBottom: 14 }}>
                <div style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 12, color: '#ffb800', marginBottom: 8 }}>⚠ MODERATE RISK</div>
                <div style={{ fontSize: 12, color: '#6e9ab5', lineHeight: 1.7 }}>Monitor traffic originating from this IP. Consider rate limiting or additional verification on requests.</div>
              </div>
            )}
            {result.abuse_score < 15 && (
              <div style={{ padding: '16px 18px', borderRadius: 8, background: 'rgba(0,255,200,0.04)', border: '1px solid rgba(0,255,200,0.15)', marginBottom: 14 }}>
                <div style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 12, color: '#00e5b0', marginBottom: 8 }}>✓ LOW RISK</div>
                <div style={{ fontSize: 12, color: '#6e9ab5', lineHeight: 1.7 }}>No significant threat indicators detected. Continue standard monitoring protocols.</div>
              </div>
            )}

            {/* Risk Score breakdown visual */}
            <div style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 10, color: '#2e5570', letterSpacing: 2, textTransform: 'uppercase', marginBottom: 12 }}>Risk Factors</div>
            {[
              { label: 'Abuse Score', pct: result.abuse_score || 0 },
              { label: 'Network Risk', pct: result.is_suspicious ? 70 : 10 },
              { label: 'Report Volume', pct: Math.min(100, ((result.total_reports || 0) / 50) * 100) },
            ].map(({ label, pct }) => {
              const c = pct >= 70 ? '#f03250' : pct >= 40 ? '#ffb800' : '#00e5b0';
              return (
                <div key={label} style={{ marginBottom: 12 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6, fontFamily: 'IBM Plex Mono, monospace', fontSize: 11 }}>
                    <span style={{ color: '#6e9ab5' }}>{label}</span>
                    <span style={{ color: c }}>{Math.round(pct)}%</span>
                  </div>
                  <div style={{ height: 4, background: 'rgba(255,255,255,0.05)', borderRadius: 2, overflow: 'hidden' }}>
                    <div style={{ width: `${pct}%`, height: '100%', background: c, borderRadius: 2, transition: 'width 1s ease', boxShadow: `0 0 6px ${c}60` }} />
                  </div>
                </div>
              );
            })}

            <div style={{ marginTop: 16, padding: '10px 14px', background: '#070d12', borderRadius: 6, fontFamily: 'IBM Plex Mono, monospace', fontSize: 10, color: '#2e5570', lineHeight: 1.7 }}>
              Powered by AbuseIPDB · Country: <span style={{ color: '#6e9ab5' }}>{result.country}</span> · Cached 1hr
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
