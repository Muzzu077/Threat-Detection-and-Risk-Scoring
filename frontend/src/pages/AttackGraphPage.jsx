import { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import * as d3 from 'd3';
import { fetchAttackGraph, fetchAttackChains, fetchEventsWithMitre } from '../api/client';
import { SeverityBadge } from '../components/Badges';

// Severity color helper
const sevColor = (score) => score >= 85 ? 'var(--accent-red)' : score >= 61 ? '#C2410C' : score >= 31 ? 'var(--accent-amber)' : 'var(--accent-green)';
const sevLabel = (score) => score >= 85 ? 'CRITICAL' : score >= 61 ? 'HIGH' : score >= 31 ? 'MEDIUM' : 'LOW';

export default function AttackGraphPage() {
  const svgRef = useRef(null);
  const navigate = useNavigate();
  const [graphData, setGraphData] = useState({ nodes: [], links: [] });
  const [chains, setChains] = useState([]);
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState(null);
  const [ipFilter, setIpFilter] = useState('');
  const [expandedEvent, setExpandedEvent] = useState(null);
  const [activeTab, setActiveTab] = useState('graph'); // 'graph' | 'logs'

  useEffect(() => {
    const load = async () => {
      try {
        const [g, c, e] = await Promise.all([
          fetchAttackGraph(),
          fetchAttackChains(),
          fetchEventsWithMitre(200, 30),
        ]);
        setGraphData(g);
        setChains(c.data || []);
        setEvents(e?.data || e || []);
      } catch {}
      setLoading(false);
    };
    load();
  }, []);

  // D3 graph rendering (keep exactly as before)
  useEffect(() => {
    if (!graphData.nodes.length || !svgRef.current) return;

    const container = svgRef.current.parentElement;
    const W = container.clientWidth || 800;
    const H = 520;

    d3.select(svgRef.current).selectAll('*').remove();
    const svg = d3.select(svgRef.current)
      .attr('width', W).attr('height', H);

    svg.append('rect').attr('width', W).attr('height', H).attr('fill', 'rgba(228, 228, 231, 0.5)');

    const g = svg.append('g');

    svg.call(d3.zoom().scaleExtent([0.3, 3]).on('zoom', (e) => {
      g.attr('transform', e.transform);
    }));

    const nodes = graphData.nodes.map(d => ({ ...d }));
    const links = graphData.links.map(d => ({ ...d, source: d.source, target: d.target }));

    const sim = d3.forceSimulation(nodes)
      .force('link', d3.forceLink(links).id(d => d.id).distance(90).strength(0.5))
      .force('charge', d3.forceManyBody().strength(-200))
      .force('center', d3.forceCenter(W / 2, H / 2))
      .force('collision', d3.forceCollide(20));

    // Warm zinc edge colors
    const link = g.append('g').selectAll('line').data(links).join('line')
      .attr('stroke', d => d.risk_score >= 85 ? '#B91C1C' : d.risk_score >= 61 ? '#C2410C' : d.risk_score >= 31 ? '#D97706' : 'rgba(161, 161, 170, 0.45)')
      .attr('stroke-width', d => d.risk_score >= 85 ? 2 : 1)
      .attr('stroke-opacity', 0.7)
      .attr('marker-end', 'url(#arrow)');

    svg.append('defs').append('marker')
      .attr('id', 'arrow').attr('viewBox', '0 -3 6 6')
      .attr('refX', 12).attr('refY', 0)
      .attr('markerWidth', 6).attr('markerHeight', 6)
      .attr('orient', 'auto')
      .append('path').attr('d', 'M0,-3L6,0L0,3').attr('fill', 'rgba(120, 113, 108, 0.5)');

    const getRadius = (type) => ({ ip: 12, user: 9, resource: 7 }[type] || 8);

    // Remap node colors to warm zinc palette
    const nodeColor = (d) => {
      const c = (d.color || '').toLowerCase();
      if (c.includes('e53e3e') || c.includes('red')) return '#B91C1C';
      if (c.includes('ed8936') || c.includes('orange')) return '#C2410C';
      if (c.includes('e6a817') || c.includes('yellow')) return '#D97706';
      if (c.includes('63b3ed') || c.includes('blue')) return '#2563EB';
      if (c.includes('b794f4') || c.includes('purple')) return '#7C3AED';
      if (c === '#ffffff' || c === 'white') return '#4A5D4F';
      return d.color || '#4A5D4F';
    };

    const node = g.append('g').selectAll('g').data(nodes).join('g')
      .style('cursor', 'pointer')
      .call(d3.drag()
        .on('start', (e, d) => { if (!e.active) sim.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
        .on('drag', (e, d) => { d.fx = e.x; d.fy = e.y; })
        .on('end', (e, d) => { if (!e.active) sim.alphaTarget(0); d.fx = null; d.fy = null; })
      )
      .on('click', (e, d) => setSelected(d));

    node.append('circle')
      .attr('r', d => getRadius(d.type))
      .attr('fill', d => nodeColor(d) + '22')
      .attr('stroke', d => nodeColor(d))
      .attr('stroke-width', 1.5)
      .style('filter', d => `drop-shadow(0 0 4px ${nodeColor(d)})`);

    node.append('text')
      .attr('text-anchor', 'middle').attr('dominant-baseline', 'central')
      .attr('font-size', d => getRadius(d.type) * 0.9)
      .attr('fill', d => nodeColor(d))
      .text(d => ({ ip: '\u2B21', user: '\u25C9', resource: '\u25AA' }[d.type] || '\u2022'));

    node.append('text')
      .attr('text-anchor', 'middle').attr('dy', d => getRadius(d.type) + 10)
      .attr('font-size', 8).attr('font-family', 'JetBrains Mono, monospace')
      .attr('fill', '#78716C')
      .text(d => d.label?.length > 14 ? d.label.slice(0, 12) + '\u2026' : d.label);

    sim.on('tick', () => {
      link.attr('x1', d => d.source.x).attr('y1', d => d.source.y)
        .attr('x2', d => d.target.x).attr('y2', d => d.target.y);
      node.attr('transform', d => `translate(${d.x},${d.y})`);
    });

    return () => sim.stop();
  }, [graphData]);

  // Filter chains by IP — handle both array and comma-separated string
  const ipQuery = ipFilter.trim().toLowerCase();
  const filteredChains = ipQuery
    ? chains.filter(c => {
        const ips = Array.isArray(c.involved_ips) ? c.involved_ips : String(c.involved_ips || '').split(',').map(s => s.trim());
        return ips.some(ip => ip.toLowerCase().includes(ipQuery));
      })
    : chains;

  // Filter events by IP
  const filteredEvents = ipQuery
    ? (Array.isArray(events) ? events : []).filter(e => (e.ip || '').toLowerCase().includes(ipQuery))
    : (Array.isArray(events) ? events : []);

  if (loading) return (
    <div className="loading"><div className="spinner"/><div className="loading-text">Building attack graph...</div></div>
  );

  return (
    <div className="page-enter">
      {/* Header */}
      <div className="flex-between mb-24">
        <div>
          <div className="page-title">{'\u2B21'} Attack Graph</div>
          <div className="page-subtitle">Kill Chain Visualization — Interactive Threat Network</div>
        </div>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-muted)' }}>
          {graphData.node_count} nodes {'\u00B7'} {graphData.link_count} edges {'\u00B7'} {filteredEvents.length} events
        </div>
      </div>

      {/* IP Search + Tab Switcher */}
      <div style={{ display: 'flex', gap: 12, alignItems: 'center', marginBottom: 20 }}>
        <div style={{ position: 'relative', flex: '0 0 320px' }}>
          <span style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-faint)', fontSize: 13 }}>{'\u2315'}</span>
          <input
            className="input"
            placeholder="Filter by IP address (e.g. 45.33.22.11)"
            value={ipFilter}
            onChange={e => setIpFilter(e.target.value)}
            style={{ paddingLeft: 32, letterSpacing: 1 }}
          />
        </div>
        {ipFilter && (
          <button className="btn btn-ghost" style={{ fontSize: 10, padding: '6px 12px' }} onClick={() => setIpFilter('')}>
            CLEAR FILTER
          </button>
        )}
        {ipFilter && (
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--accent-amber)' }}>
            {filteredChains.length} chains {'\u00B7'} {filteredEvents.length} events matching "{ipFilter}"
          </span>
        )}
        <div style={{ marginLeft: 'auto', display: 'flex', gap: 4 }}>
          {['graph', 'logs'].map(tab => (
            <button key={tab} onClick={() => setActiveTab(tab)} style={{
              padding: '6px 14px', borderRadius: 'var(--radius-sm)', fontFamily: 'var(--font-mono)', fontSize: 11,
              cursor: 'pointer', border: 'none', transition: 'all 0.2s', textTransform: 'uppercase', letterSpacing: 1,
              background: activeTab === tab ? 'rgba(255,255,255,0.55)' : 'transparent',
              color: activeTab === tab ? 'var(--text-primary)' : 'var(--text-muted)',
              outline: `1px solid ${activeTab === tab ? 'var(--border-mid)' : 'var(--border-dim)'}`,
            }}>
              {tab === 'graph' ? '\u2B21 Graph' : '\u25A6 Event Logs'}
            </button>
          ))}
        </div>
      </div>

      {/* Tab: GRAPH VIEW */}
      {activeTab === 'graph' && (
        <div className="grid-2 mb-16" style={{ gridTemplateColumns: '2fr 1fr' }}>
          {/* D3 Graph */}
          <div className="graph-container" style={{ height: 560 }}>
            <div className="graph-legend">
              {[
                { color: '#B91C1C', label: 'CRITICAL (>85)' },
                { color: '#C2410C', label: 'HIGH (>61)' },
                { color: '#D97706', label: 'MEDIUM (>31)' },
                { color: '#4A5D4F', label: 'LOW (<31)' },
              ].map(l => (
                <div key={l.label} className="legend-item">
                  <div className="legend-dot" style={{ background: l.color }} />
                  {l.label}
                </div>
              ))}
              <div className="legend-item">{'\u2B21'} IP &nbsp;&nbsp; {'\u25C9'} USER &nbsp;&nbsp; {'\u25AA'} RESOURCE</div>
            </div>

            {graphData.nodes.length === 0 ? (
              <div className="p-empty" style={{ padding: 80 }}>
                NO HIGH-RISK EVENTS TO GRAPH<br />
                <span style={{ fontSize: 10, marginTop: 8, display: 'block' }}>
                  Generate traffic with the traffic simulator to see attack paths
                </span>
              </div>
            ) : (
              <svg ref={svgRef} style={{ width: '100%', height: 520, display: 'block' }} />
            )}
          </div>

          {/* Node Detail + Kill Chains */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            {/* Selected Node */}
            <div className="card" style={{ minHeight: 140 }}>
              <div className="section-header">
                <div className="section-title">{'\u25C9'} Selected Node</div>
              </div>
              {selected ? (
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>
                  {[
                    ['ID', selected.id],
                    ['Type', selected.type?.toUpperCase()],
                    ['Label', selected.label],
                    ['Severity', <SeverityBadge severity={selected.severity} />],
                    ['Risk Score', Math.round(selected.risk_score || 0)],
                  ].map(([k, v]) => (
                    <div key={k} className="flex-between" style={{ padding: '4px 0', borderBottom: '1px solid var(--border-dim)' }}>
                      <span style={{ color: 'var(--text-muted)', fontSize: 10 }}>{k}</span>
                      <span style={{ color: 'var(--text-primary)' }}>{v}</span>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="p-empty" style={{ padding: 20 }}>Click a node to inspect</div>
              )}
            </div>

            {/* Kill Chains */}
            <div className="card" style={{ flex: 1, overflow: 'hidden' }}>
              <div className="section-header flex-between">
                <div className="section-title">{'\uD83D\uDD17'} Kill Chains</div>
                <span className="section-count">{filteredChains.length} detected</span>
              </div>
              <div style={{ overflowY: 'auto', maxHeight: 340 }}>
                {filteredChains.length === 0 ? (
                  <div className="p-empty" style={{ padding: 20 }}>
                    {ipFilter ? `No kill chains matching "${ipFilter}"` : 'No kill chains detected'}
                  </div>
                ) : filteredChains.slice(0, 10).map(chain => (
                  <div key={chain.chain_id} style={{
                    background: 'var(--bg-glass)', backdropFilter: 'blur(8px)', borderRadius: 'var(--radius-sm)', padding: '10px 12px',
                    marginBottom: 8, borderLeft: `3px solid ${chain.severity === 'critical' ? 'var(--accent-red)' : chain.severity === 'high' ? '#C2410C' : 'var(--accent-amber)'}`,
                    border: '1px solid var(--border-dim)', borderLeftWidth: 3,
                  }}>
                    <div className="flex-between mb-8">
                      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-primary)' }}>{chain.chain_id}</span>
                      <SeverityBadge severity={chain.severity} />
                    </div>
                    <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)' }}>
                      {chain.events.length} events {'\u00B7'} Risk: {Math.round(chain.max_risk)}<br />
                      IPs: {chain.involved_ips.join(', ') || 'N/A'}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Tab: EVENT LOG EXPLORER */}
      {activeTab === 'logs' && (
        <div style={{ background: 'var(--bg-card)', backdropFilter: 'blur(16px)', border: '1px solid var(--border-light)', borderRadius: 'var(--radius-lg)', overflow: 'hidden', boxShadow: 'var(--shadow-sm)' }}>
          <div style={{ padding: '14px 20px', borderBottom: '1px solid var(--border-dim)', fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', letterSpacing: 3, textTransform: 'uppercase', display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'rgba(255,255,255,0.2)' }}>
            <span>{'\u25A6'} Individual Event Logs ({filteredEvents.length} events with risk {'\u2265'} 30)</span>
            <span style={{ color: 'var(--text-secondary)', letterSpacing: 1 }}>Click any row to expand details</span>
          </div>

          <div style={{ maxHeight: 600, overflowY: 'auto' }}>
            {filteredEvents.length === 0 ? (
              <div className="p-empty" style={{ padding: 40 }}>
                {ipFilter ? `No events matching "${ipFilter}"` : 'No high-risk events found. Run traffic simulator to generate data.'}
              </div>
            ) : filteredEvents.map((evt, idx) => {
              const isExpanded = expandedEvent === evt.id;
              const color = sevColor(evt.risk_score || 0);
              return (
                <div key={evt.id || idx}>
                  {/* Row */}
                  <div
                    onClick={() => setExpandedEvent(isExpanded ? null : evt.id)}
                    style={{
                      display: 'flex', alignItems: 'center', gap: 12,
                      padding: '10px 20px',
                      borderBottom: '1px solid var(--border-dim)',
                      cursor: 'pointer', transition: 'background 0.15s',
                      background: isExpanded ? 'rgba(255,255,255,0.3)' : 'transparent',
                      borderLeft: `3px solid ${color}`,
                    }}
                    onMouseEnter={e => { if (!isExpanded) e.currentTarget.style.background = 'rgba(255,255,255,0.15)'; }}
                    onMouseLeave={e => { if (!isExpanded) e.currentTarget.style.background = 'transparent'; }}
                  >
                    {/* Expand arrow */}
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-faint)', width: 16, flexShrink: 0, transition: 'transform 0.2s', transform: isExpanded ? 'rotate(90deg)' : 'rotate(0deg)' }}>
                      {'\u25B6'}
                    </span>

                    {/* Timestamp */}
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', width: 130, flexShrink: 0 }}>
                      {evt.timestamp ? new Date(evt.timestamp).toLocaleString('en-US', { month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }) : '--'}
                    </span>

                    {/* Risk badge */}
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color, background: `${color}15`, border: `1px solid ${color}30`, padding: '2px 8px', borderRadius: 3, width: 40, textAlign: 'center', flexShrink: 0 }}>
                      {Math.round(evt.risk_score || 0)}
                    </span>

                    {/* IP */}
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-primary)', width: 130, flexShrink: 0 }}>
                      {evt.ip || '--'}
                    </span>

                    {/* User */}
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--accent)', width: 140, flexShrink: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {evt.user || '--'}
                    </span>

                    {/* Attack type */}
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: '#C2410C', background: 'rgba(234,88,12,0.08)', border: '1px solid rgba(234,88,12,0.2)', padding: '2px 8px', borderRadius: 3, flexShrink: 0 }}>
                      {(evt.attack_type || 'unknown').replace(/_/g, ' ').toUpperCase()}
                    </span>

                    {/* MITRE ID */}
                    {evt.mitre_id && evt.mitre_id !== 'None' && (
                      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--accent-blue)', background: 'rgba(37,99,235,0.08)', border: '1px solid rgba(37,99,235,0.2)', padding: '2px 6px', borderRadius: 3, flexShrink: 0 }}>
                        {evt.mitre_id}
                      </span>
                    )}

                    {/* Action */}
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-secondary)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {evt.action || '--'}
                    </span>

                    {/* Navigate arrow */}
                    <span
                      onClick={(e) => { e.stopPropagation(); if (evt.incident_id) navigate(`/incidents/${evt.incident_id}`); }}
                      style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: evt.incident_id ? 'var(--accent)' : 'var(--text-faint)', cursor: evt.incident_id ? 'pointer' : 'default', flexShrink: 0 }}
                      title={evt.incident_id ? `Go to INC-${String(evt.incident_id).padStart(4, '0')}` : 'No incident created (risk below threshold)'}
                    >
                      {evt.incident_id ? `INC-${String(evt.incident_id).padStart(4, '0')} \u2192` : ''}
                    </span>
                  </div>

                  {/* Expanded Detail Panel */}
                  {isExpanded && (
                    <div style={{ background: 'var(--bg-glass-heavy)', backdropFilter: 'blur(12px)', padding: '16px 20px 16px 44px', borderBottom: '1px solid var(--border-dim)', animation: 'fadeIn 0.2s ease' }}>
                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 14, marginBottom: 14 }}>
                        {[
                          { label: 'RISK SCORE', value: Math.round(evt.risk_score || 0), color },
                          { label: 'ML CONFIDENCE', value: `${Math.round(evt.ml_confidence || 0)}%`, color: 'var(--accent-blue)' },
                          { label: 'COUNTRY', value: evt.country || 'UNKNOWN', color: 'var(--text-secondary)' },
                        ].map(kpi => (
                          <div key={kpi.label} style={{ background: 'var(--bg-card)', backdropFilter: 'blur(8px)', borderRadius: 'var(--radius-sm)', padding: '10px 14px', border: '1px solid var(--border-dim)' }}>
                            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 8, color: 'var(--text-muted)', letterSpacing: 2, marginBottom: 4 }}>{kpi.label}</div>
                            <div style={{ fontFamily: 'var(--font-display)', fontSize: 18, color: kpi.color }}>{kpi.value}</div>
                          </div>
                        ))}
                      </div>

                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                        {[
                          ['IP Address', evt.ip],
                          ['User', evt.user],
                          ['Role', evt.role || '--'],
                          ['Action', evt.action],
                          ['Resource', evt.resource || '--'],
                          ['Status', evt.status || '--'],
                          ['Attack Type', (evt.attack_type || 'unknown').replace(/_/g, ' ')],
                          ['MITRE Technique', evt.mitre_id || '--'],
                          ['MITRE Tactic', evt.mitre_tactic || '--'],
                          ['Threat Intel Score', `${evt.threat_intel_score || 0}%`],
                        ].map(([k, v]) => (
                          <div key={k} style={{ display: 'flex', justifyContent: 'space-between', padding: '4px 0', borderBottom: '1px solid var(--border-dim)' }}>
                            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)' }}>{k}</span>
                            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-primary)' }}>{v}</span>
                          </div>
                        ))}
                      </div>

                      {/* Risk breakdown bars */}
                      <div style={{ marginTop: 14 }}>
                        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-muted)', letterSpacing: 2, marginBottom: 8 }}>RISK BREAKDOWN</div>
                        {[
                          { label: 'Anomaly Score', val: evt.anomaly_score },
                          { label: 'Time Risk', val: evt.time_risk },
                          { label: 'Role Risk', val: evt.role_risk },
                          { label: 'Resource Risk', val: evt.resource_risk },
                        ].map(row => {
                          const pct = Math.min(100, Math.max(0, row.val || 0));
                          const barColor = pct >= 70 ? 'var(--accent-red)' : pct >= 40 ? 'var(--accent-amber)' : 'var(--accent-green)';
                          return (
                            <div key={row.label} style={{ marginBottom: 6 }}>
                              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 2 }}>
                                <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-muted)' }}>{row.label}</span>
                                <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: barColor }}>{Math.round(pct)}</span>
                              </div>
                              <div style={{ height: 3, background: 'var(--bg-elevated)', borderRadius: 2, overflow: 'hidden' }}>
                                <div style={{ width: `${pct}%`, height: '100%', background: barColor, borderRadius: 2, transition: 'width 0.6s ease' }} />
                              </div>
                            </div>
                          );
                        })}
                      </div>

                      {evt.incident_id && (
                        <button
                          className="btn btn-primary"
                          style={{ marginTop: 12, fontSize: 10, padding: '6px 14px' }}
                          onClick={() => navigate(`/incidents/${evt.incident_id}`)}
                        >
                          INVESTIGATE INC-{String(evt.incident_id).padStart(4, '0')} {'\u2192'}
                        </button>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
