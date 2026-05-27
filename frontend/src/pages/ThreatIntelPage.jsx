import { useState, useEffect } from 'react';
import { fetchThreatIntel, fetchOsintFeeds } from '../api/client';

const QUICK_IPS = ['45.33.22.11', '182.21.4.9', '185.220.101.3', '8.8.8.8', '1.1.1.1'];

function ScoreGauge({ score }) {
  const color = score >= 75 ? 'var(--accent-red)' : score >= 40 ? 'var(--accent-amber)' : score >= 15 ? 'var(--accent-amber)' : 'var(--accent-green)';
  const colorRaw = score >= 75 ? '#B91C1C' : score >= 40 ? '#D97706' : score >= 15 ? '#D97706' : '#059669';
  const label = score >= 75 ? 'CRITICAL THREAT' : score >= 40 ? 'HIGH RISK' : score >= 15 ? 'MODERATE' : 'CLEAN';
  return (
    <div style={{ marginBottom: 24 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', marginBottom: 10 }}>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, letterSpacing: 3, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Abuse Confidence Score</div>
        <div style={{ display: 'flex', alignItems: 'baseline', gap: 8 }}>
          <span style={{ fontFamily: 'var(--font-display)', fontSize: 36, color }}>{score}</span>
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 14, color: 'var(--text-muted)' }}>%</span>
        </div>
      </div>
      <div style={{ height: 8, background: 'var(--border-dim)', borderRadius: 4, overflow: 'hidden', position: 'relative' }}>
        <div style={{ position: 'absolute', inset: 0, background: 'repeating-linear-gradient(90deg, transparent, transparent 9px, rgba(161,161,170,0.08) 9px, rgba(161,161,170,0.08) 10px)' }} />
        <div style={{ width: `${score}%`, height: '100%', background: `linear-gradient(90deg, var(--accent), ${colorRaw})`, borderRadius: 4, transition: 'width 1.2s ease' }} />
      </div>
      <div style={{ marginTop: 8, display: 'flex', justifyContent: 'space-between', fontFamily: 'var(--font-mono)', fontSize: 10 }}>
        <span style={{ color: 'var(--text-faint)' }}>Safe</span>
        <span style={{ color }}>▲ {label}</span>
        <span style={{ color: 'var(--text-faint)' }}>Malicious</span>
      </div>
    </div>
  );
}

export default function ThreatIntelPage() {
  const [ip, setIp] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [osint, setOsint] = useState(null);

  useEffect(() => {
    fetchOsintFeeds().then(setOsint).catch(() => {});
  }, []);

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

  const scoreColor = result ? (result.abuse_score >= 75 ? 'var(--accent-red)' : result.abuse_score >= 40 ? 'var(--accent-amber)' : result.abuse_score >= 15 ? 'var(--accent-amber)' : 'var(--accent-green)') : 'var(--accent-green)';
  const scoreColorRaw = result ? (result.abuse_score >= 75 ? '#B91C1C' : result.abuse_score >= 40 ? '#D97706' : result.abuse_score >= 15 ? '#D97706' : '#059669') : '#059669';

  return (
    <div className="page-enter">

      {/* Header */}
      <div style={{ marginBottom: 28 }}>
        <div className="page-title">
          Threat Intelligence
        </div>
        <div className="page-subtitle">
          IP Reputation Lookup — AbuseIPDB Integration
        </div>
      </div>

      {/* Notice */}
      <div style={{ padding: '12px 18px', borderRadius: 'var(--radius-sm)', background: 'rgba(217,119,6,0.08)', border: '1px solid rgba(217,119,6,0.22)', marginBottom: 24, fontFamily: 'var(--font-body)', fontSize: 12, color: 'var(--accent-amber)', display: 'flex', alignItems: 'center', gap: 10, fontWeight: 500 }}>
        <span>⚠</span>
        <span>Set <span style={{ color: 'var(--text-primary)', fontWeight: 600 }}>ABUSEIPDB_API_KEY</span> in <span style={{ color: 'var(--text-primary)', fontWeight: 600 }}>.env</span> for live threat data. Free tier: 1,000 checks/day.</span>
      </div>

      {/* Lookup Form */}
      <div style={{ background: 'var(--bg-card)', backdropFilter: 'blur(16px)', border: '1px solid var(--border-light)', borderRadius: 'var(--radius-lg)', padding: 24, marginBottom: 24, boxShadow: 'var(--shadow-sm)' }}>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', letterSpacing: 3, textTransform: 'uppercase', marginBottom: 16 }}>IP Lookup</div>
        <form onSubmit={handleCheck}>
          <div style={{ display: 'flex', gap: 10, marginBottom: 14, alignItems: 'center' }}>
            <div style={{ flex: 1, maxWidth: 380, position: 'relative' }}>
              <span style={{ position: 'absolute', left: 14, top: '50%', transform: 'translateY(-50%)', fontSize: 13, color: 'var(--text-faint)' }}>⌕</span>
              <input className="input" placeholder="Enter IP address (e.g. 45.33.22.11)"
                value={ip} onChange={e => setIp(e.target.value)} style={{ paddingLeft: 34, letterSpacing: 1 }} />
            </div>
            <button type="submit" className="btn btn-primary" disabled={loading} style={{ minWidth: 130 }}>
              {loading ? <><span className="spinner" style={{ width: 12, height: 12, borderWidth: 1.5 }} /> SCANNING...</> : '◉ ANALYZE IP'}
            </button>
          </div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', letterSpacing: 2 }}>QUICK TEST:</span>
            {QUICK_IPS.map(testIp => (
              <button key={testIp} type="button" onClick={() => setIp(testIp)} style={{
                padding: '4px 12px', borderRadius: 'var(--radius-sm)', fontFamily: 'var(--font-mono)', fontSize: 10,
                background: ip === testIp ? 'var(--bg-glass-heavy)' : 'transparent', color: ip === testIp ? 'var(--text-primary)' : 'var(--text-muted)',
                border: `1px solid ${ip === testIp ? 'var(--border-bright)' : 'var(--border-dim)'}`, cursor: 'pointer', transition: 'all 0.2s', letterSpacing: 1
              }}>
                {testIp}
              </button>
            ))}
          </div>
        </form>
      </div>

      {error && (
        <div style={{ padding: '14px 18px', borderRadius: 'var(--radius-sm)', background: 'rgba(185,28,28,0.08)', border: '1px solid rgba(185,28,28,0.22)', fontFamily: 'var(--font-body)', fontSize: 12, color: 'var(--accent-red)', marginBottom: 24, fontWeight: 500 }}>
          ✘ {error}
        </div>
      )}

      {result && (
        <div className="fade-in" style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr', gap: 16 }}>

          {/* Main Result Panel */}
          <div style={{ background: 'var(--bg-card)', backdropFilter: 'blur(16px)', border: `1px solid ${result.is_suspicious ? 'rgba(185,28,28,0.22)' : 'var(--border-light)'}`, borderRadius: 'var(--radius-lg)', padding: 24, position: 'relative', overflow: 'hidden', boxShadow: 'var(--shadow-sm)' }}>
            <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 3, background: `linear-gradient(90deg, transparent, ${scoreColorRaw}, transparent)` }} />

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 20 }}>
              <div>
                <div style={{ fontFamily: 'var(--font-display)', fontSize: 18, color: 'var(--text-primary)', letterSpacing: 0.5 }}>{result.ip}</div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', letterSpacing: 2, marginTop: 4 }}>IPv4 ADDRESS</div>
              </div>
              <span style={{
                padding: '6px 14px', borderRadius: 'var(--radius-sm)', fontFamily: 'var(--font-mono)', fontSize: 11, letterSpacing: 2, textTransform: 'uppercase', fontWeight: 500,
                background: result.is_suspicious ? 'rgba(185,28,28,0.10)' : 'rgba(5,150,105,0.10)',
                color: result.is_suspicious ? 'var(--accent-red)' : 'var(--accent-green)',
                border: `1px solid ${result.is_suspicious ? 'rgba(185,28,28,0.22)' : 'rgba(5,150,105,0.22)'}`,
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
                <div key={label} style={{ padding: '12px 14px', background: 'var(--bg-glass)', backdropFilter: 'blur(12px)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-dim)' }}>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-muted)', letterSpacing: 2, textTransform: 'uppercase', marginBottom: 6 }}>{label}</div>
                  <div style={{ fontFamily: 'var(--font-body)', fontSize: 13, color: 'var(--text-primary)', fontWeight: 500 }}>{icon} {value}</div>
                </div>
              ))}
            </div>
          </div>

          {/* Threat Assessment Panel */}
          <div style={{ background: 'var(--bg-card)', backdropFilter: 'blur(16px)', border: '1px solid var(--border-light)', borderRadius: 'var(--radius-lg)', padding: 24, boxShadow: 'var(--shadow-sm)' }}>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', letterSpacing: 3, textTransform: 'uppercase', marginBottom: 18 }}>Threat Assessment</div>

            {/* Recommendation box */}
            {result.abuse_score >= 75 && (
              <div style={{ padding: '16px 18px', borderRadius: 'var(--radius-sm)', background: 'rgba(185,28,28,0.08)', border: '1px solid rgba(185,28,28,0.22)', marginBottom: 14 }}>
                <div style={{ fontFamily: 'var(--font-body)', fontSize: 12, color: 'var(--accent-red)', marginBottom: 8, fontWeight: 600 }}>🚨 HIGH CONFIDENCE THREAT</div>
                <div style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.7 }}>Immediate blocking recommended. This IP shows {result.abuse_score}% abuse confidence with {result.total_reports} reports in the database.</div>
              </div>
            )}
            {result.abuse_score >= 15 && result.abuse_score < 75 && (
              <div style={{ padding: '16px 18px', borderRadius: 'var(--radius-sm)', background: 'rgba(217,119,6,0.08)', border: '1px solid rgba(217,119,6,0.22)', marginBottom: 14 }}>
                <div style={{ fontFamily: 'var(--font-body)', fontSize: 12, color: 'var(--accent-amber)', marginBottom: 8, fontWeight: 600 }}>⚠ MODERATE RISK</div>
                <div style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.7 }}>Monitor traffic originating from this IP. Consider rate limiting or additional verification on requests.</div>
              </div>
            )}
            {result.abuse_score < 15 && (
              <div style={{ padding: '16px 18px', borderRadius: 'var(--radius-sm)', background: 'rgba(5,150,105,0.08)', border: '1px solid rgba(5,150,105,0.18)', marginBottom: 14 }}>
                <div style={{ fontFamily: 'var(--font-body)', fontSize: 12, color: 'var(--accent-green)', marginBottom: 8, fontWeight: 600 }}>✓ LOW RISK</div>
                <div style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.7 }}>No significant threat indicators detected. Continue standard monitoring protocols.</div>
              </div>
            )}

            {/* Risk Score breakdown visual */}
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', letterSpacing: 2, textTransform: 'uppercase', marginBottom: 12 }}>Risk Factors</div>
            {[
              { label: 'Abuse Score', pct: result.abuse_score || 0 },
              { label: 'Network Risk', pct: result.is_suspicious ? 70 : 10 },
              { label: 'Report Volume', pct: Math.min(100, ((result.total_reports || 0) / 50) * 100) },
            ].map(({ label, pct }) => {
              const c = pct >= 70 ? 'var(--accent-red)' : pct >= 40 ? 'var(--accent-amber)' : 'var(--accent-green)';
              return (
                <div key={label} style={{ marginBottom: 12 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6, fontFamily: 'var(--font-mono)', fontSize: 11 }}>
                    <span style={{ color: 'var(--text-secondary)' }}>{label}</span>
                    <span style={{ color: c }}>{Math.round(pct)}%</span>
                  </div>
                  <div style={{ height: 4, background: 'var(--border-dim)', borderRadius: 2, overflow: 'hidden' }}>
                    <div style={{ width: `${pct}%`, height: '100%', background: c, borderRadius: 2, transition: 'width 1s ease' }} />
                  </div>
                </div>
              );
            })}

            <div style={{ marginTop: 16, padding: '10px 14px', background: 'var(--bg-glass)', backdropFilter: 'blur(12px)', borderRadius: 'var(--radius-sm)', fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-faint)', lineHeight: 1.7, border: '1px solid var(--border-dim)' }}>
              Powered by AbuseIPDB · Country: <span style={{ color: 'var(--text-secondary)' }}>{result.country}</span> · Cached 1hr
            </div>
          </div>
        </div>
      )}

      {/* OSINT Threat Feeds */}
      <div style={{ marginTop: 24, background: 'var(--bg-card)', backdropFilter: 'blur(16px)', border: '1px solid var(--border-light)', borderRadius: 'var(--radius-lg)', padding: 24, boxShadow: 'var(--shadow-sm)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', letterSpacing: 3, textTransform: 'uppercase' }}>OSINT Threat Intelligence Feeds</div>
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-primary)', fontWeight: 500 }}>
            {osint?.total_indicators || 0} indicators loaded
          </span>
        </div>
        {osint?.feeds?.map(feed => (
          <div key={feed.name} style={{ padding: '12px 14px', background: 'var(--bg-glass)', backdropFilter: 'blur(12px)', borderRadius: 'var(--radius-sm)', marginBottom: 8, border: '1px solid var(--border-dim)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <div style={{ fontFamily: 'var(--font-body)', fontSize: 12, color: 'var(--text-primary)', marginBottom: 4, fontWeight: 500 }}>{feed.name}</div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)' }}>{feed.description}</div>
            </div>
            <div style={{ textAlign: 'right' }}>
              <div style={{ fontFamily: 'var(--font-display)', fontSize: 18, color: feed.cached ? 'var(--text-primary)' : 'var(--text-faint)' }}>{feed.count || 0}</div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: feed.cached ? 'var(--accent-green)' : 'var(--accent-amber)' }}>
                {feed.cached ? 'LOADED' : 'NOT CACHED'}
              </div>
            </div>
          </div>
        ))}
        {!osint && (
          <div style={{ textAlign: 'center', padding: '24px 0', fontFamily: 'var(--font-body)', fontSize: 11, color: 'var(--text-muted)' }}>
            Loading OSINT feeds...
          </div>
        )}
      </div>
    </div>
  );
}
