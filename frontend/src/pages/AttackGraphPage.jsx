import { useEffect, useRef, useState } from 'react';
import * as d3 from 'd3';
import { fetchAttackGraph, fetchAttackChains } from '../api/client';
import { SeverityBadge } from '../components/Badges';

export default function AttackGraphPage() {
  const svgRef = useRef(null);
  const [graphData, setGraphData] = useState({ nodes: [], links: [] });
  const [chains, setChains] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState(null);

  useEffect(() => {
    const load = async () => {
      try {
        const [g, c] = await Promise.all([fetchAttackGraph(), fetchAttackChains()]);
        setGraphData(g);
        setChains(c.data || []);
      } catch {}
      setLoading(false);
    };
    load();
  }, []);

  useEffect(() => {
    if (!graphData.nodes.length || !svgRef.current) return;

    const container = svgRef.current.parentElement;
    const W = container.clientWidth || 800;
    const H = 520;

    d3.select(svgRef.current).selectAll('*').remove();
    const svg = d3.select(svgRef.current)
      .attr('width', W).attr('height', H);

    // Background
    svg.append('rect').attr('width', W).attr('height', H).attr('fill', '#030609');

    const g = svg.append('g');

    // Zoom
    svg.call(d3.zoom().scaleExtent([0.3, 3]).on('zoom', (e) => {
      g.attr('transform', e.transform);
    }));

    const nodes = graphData.nodes.map(d => ({ ...d }));
    const links = graphData.links.map(d => ({
      ...d,
      source: d.source,
      target: d.target,
    }));

    const sim = d3.forceSimulation(nodes)
      .force('link', d3.forceLink(links).id(d => d.id).distance(90).strength(0.5))
      .force('charge', d3.forceManyBody().strength(-200))
      .force('center', d3.forceCenter(W / 2, H / 2))
      .force('collision', d3.forceCollide(20));

    // Links
    const link = g.append('g').selectAll('line').data(links).join('line')
      .attr('stroke', d => {
        if (d.risk_score >= 85) return '#f03250';
        if (d.risk_score >= 61) return '#ff8c00';
        if (d.risk_score >= 31) return '#ffb800';
        return '#1e3a4a';
      })
      .attr('stroke-width', d => d.risk_score >= 85 ? 2 : 1)
      .attr('stroke-opacity', 0.6)
      .attr('marker-end', 'url(#arrow)');

    // Arrow marker
    svg.append('defs').append('marker')
      .attr('id', 'arrow').attr('viewBox', '0 -3 6 6')
      .attr('refX', 12).attr('refY', 0)
      .attr('markerWidth', 6).attr('markerHeight', 6)
      .attr('orient', 'auto')
      .append('path').attr('d', 'M0,-3L6,0L0,3').attr('fill', 'rgba(0,255,200,0.4)');

    // Node sizes by type
    const getRadius = (type) => ({ ip: 12, user: 9, resource: 7 }[type] || 8);

    // Nodes
    const node = g.append('g').selectAll('g').data(nodes).join('g')
      .style('cursor', 'pointer')
      .call(d3.drag()
        .on('start', (e, d) => { if (!e.active) sim.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
        .on('drag', (e, d) => { d.fx = e.x; d.fy = e.y; })
        .on('end', (e, d) => { if (!e.active) sim.alphaTarget(0); d.fx = null; d.fy = null; })
      )
      .on('click', (e, d) => setSelected(d));

    // Node circle with glow
    node.append('circle')
      .attr('r', d => getRadius(d.type))
      .attr('fill', d => d.color + '22')
      .attr('stroke', d => d.color)
      .attr('stroke-width', 1.5)
      .style('filter', d => `drop-shadow(0 0 4px ${d.color})`);

    // Icon label by type
    node.append('text')
      .attr('text-anchor', 'middle').attr('dominant-baseline', 'central')
      .attr('font-size', d => getRadius(d.type) * 0.9)
      .attr('fill', d => d.color)
      .text(d => ({ ip: '⬡', user: '◉', resource: '▪' }[d.type] || '•'));

    // Node label below
    node.append('text')
      .attr('text-anchor', 'middle').attr('dy', d => getRadius(d.type) + 10)
      .attr('font-size', 8).attr('font-family', 'IBM Plex Mono, monospace')
      .attr('fill', '#6e9ab5')
      .text(d => d.label?.length > 14 ? d.label.slice(0, 12) + '…' : d.label);

    sim.on('tick', () => {
      link
        .attr('x1', d => d.source.x).attr('y1', d => d.source.y)
        .attr('x2', d => d.target.x).attr('y2', d => d.target.y);
      node.attr('transform', d => `translate(${d.x},${d.y})`);
    });

    return () => sim.stop();
  }, [graphData]);

  if (loading) return (
    <div className="loading"><div className="spinner"/><div className="loading-text">Building attack graph...</div></div>
  );

  return (
    <div className="fade-in">
      <div className="flex-between mb-24">
        <div>
          <div className="page-title">⬡ ATTACK GRAPH</div>
          <div className="page-subtitle">Kill Chain Visualization — Interactive Threat Network</div>
        </div>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-muted)' }}>
          {graphData.node_count} nodes · {graphData.link_count} edges
        </div>
      </div>

      <div className="grid-2 mb-16" style={{ gridTemplateColumns: '2fr 1fr' }}>
        {/* D3 Graph */}
        <div className="graph-container" style={{ height: 560 }}>
          <div className="graph-legend">
            {[
              { color: '#f03250', label: 'CRITICAL (>85)' },
              { color: '#ff8c00', label: 'HIGH (>61)' },
              { color: '#ffb800', label: 'MEDIUM (>31)' },
              { color: '#00e5b0', label: 'LOW (<31)' },
            ].map(l => (
              <div key={l.label} className="legend-item">
                <div className="legend-dot" style={{ background: l.color }} />
                {l.label}
              </div>
            ))}
            <div className="legend-item">⬡ IP &nbsp;&nbsp; ◉ USER &nbsp;&nbsp; ▪ RESOURCE</div>
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
              <div className="section-title">◉ SELECTED NODE</div>
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
              <div className="section-title">🔗 KILL CHAINS</div>
              <span className="section-count">{chains.length} detected</span>
            </div>
            <div style={{ overflowY: 'auto', maxHeight: 340 }}>
              {chains.length === 0 ? (
                <div className="p-empty" style={{ padding: 20 }}>No kill chains detected</div>
              ) : chains.slice(0, 10).map(chain => (
                <div key={chain.chain_id} style={{
                  background: 'var(--bg-elevated)', borderRadius: 6, padding: '10px 12px',
                  marginBottom: 8, borderLeft: `2px solid ${chain.severity === 'critical' ? '#f03250' : chain.severity === 'high' ? '#ff8c00' : '#ffb800'}`
                }}>
                  <div className="flex-between mb-8">
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-primary)' }}>{chain.chain_id}</span>
                    <SeverityBadge severity={chain.severity} />
                  </div>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)' }}>
                    {chain.events.length} events · Risk: {Math.round(chain.max_risk)}<br />
                    IPs: {chain.involved_ips.join(', ') || 'N/A'}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
