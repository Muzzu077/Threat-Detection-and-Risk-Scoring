import { useEffect, useRef, useState } from 'react';
import { getSeverity } from '../utils/helpers';

export default function LiveFeed() {
  const [events, setEvents] = useState([]);
  const feedRef = useRef(null);
  const wsRef = useRef(null);

  const formatTime = (ts) => {
    if (!ts) return '--:--:--';
    return new Date(ts).toLocaleTimeString('en-US', { hour12: false });
  };

  const getSeverityClass = (score) => {
    const sev = getSeverity(score || 0);
    return `entry-${sev}`;
  };

  const getRiskColor = (score) => {
    if (score >= 85) return '#f03250';
    if (score >= 61) return '#ff8c00';
    if (score >= 31) return '#ffb800';
    return '#00e5b0';
  };

  useEffect(() => {
    const connect = () => {
      try {
        const ws = new WebSocket(`ws://${window.location.host}/ws/live-feed`);
        wsRef.current = ws;

        ws.onmessage = (e) => {
          const msg = JSON.parse(e.data);
          if (msg.type === 'ping') return;
          if (msg.type === 'new_event' || msg.type === 'history_event') {
            setEvents(prev => {
              const next = [msg.data, ...prev];
              return next.slice(0, 200); // keep last 200
            });
          }
        };

        ws.onclose = () => {
          setTimeout(connect, 3000);
        };

        ws.onerror = () => {
          ws.close();
        };
      } catch (err) {
        setTimeout(connect, 5000);
      }
    };

    connect();
    return () => wsRef.current?.close();
  }, []);

  return (
    <div className="live-feed">
      <div className="feed-header">
        <div className="live-dot" />
        <span className="feed-title">Live Telemetry Feed</span>
        <span style={{ marginLeft: 'auto', fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)' }}>
          {events.length} events
        </span>
      </div>

      <div ref={feedRef}>
        {events.length === 0 ? (
          <div className="p-empty">AWAITING TELEMETRY STREAM...</div>
        ) : (
          events.map((evt, i) => (
            <div
              key={`${evt.id}-${i}`}
              className={`feed-entry ${getSeverityClass(evt.risk_score)}`}
            >
              <span className="feed-time">{formatTime(evt.timestamp)}</span>
              <span className="feed-risk" style={{ color: getRiskColor(evt.risk_score) }}>
                {Math.round(evt.risk_score || 0)}
              </span>
              <span className="feed-user">{evt.user}</span>
              <span className="feed-action">
                {evt.action}
                {evt.attack_type && evt.attack_type !== 'normal' && evt.attack_type !== 'unknown' && (
                  <span style={{ marginLeft: 6, color: '#ff8c00', fontSize: 10 }}>
                    [{evt.attack_type}]
                  </span>
                )}
              </span>
              <span className="feed-country">{evt.country || '??'}</span>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
