import { useState } from 'react';

const TABS = [
  { id: 'nodejs', label: 'NODE.JS' },
  { id: 'python', label: 'PYTHON' },
  { id: 'rest', label: 'REST API' },
];

const TAB_CONTENT = {
  nodejs: {
    title: 'Node.js SDK Integration',
    sections: [
      {
        heading: '01 // INSTALLATION',
        code: 'npm install threatpulse-sdk',
      },
      {
        heading: '02 // INITIALIZE CLIENT',
        code: `const { ThreatPulse } = require('threatpulse-sdk');
const tp = new ThreatPulse({ apiKey: process.env.THREATPULSE_API_KEY });`,
      },
      {
        heading: '03 // EXPRESS MIDDLEWARE',
        description: 'Automatically analyze all incoming requests for threats.',
        code: `const { threatPulseMiddleware } = require('threatpulse-sdk/express');
app.use(threatPulseMiddleware({ apiKey: process.env.THREATPULSE_API_KEY }));`,
      },
    ],
  },
  python: {
    title: 'Python SDK Integration',
    sections: [
      {
        heading: '01 // INSTALLATION',
        code: 'pip install threatpulse-sdk',
      },
      {
        heading: '02 // INITIALIZE CLIENT',
        code: `from threatpulse import ThreatPulse
tp = ThreatPulse(api_key=os.environ['THREATPULSE_API_KEY'])`,
      },
      {
        heading: '03 // FLASK MIDDLEWARE',
        description: 'Wrap your WSGI application to monitor all requests.',
        code: `from threatpulse.middleware import ThreatPulseMiddleware
app.wsgi_app = ThreatPulseMiddleware(app.wsgi_app, api_key=os.environ['THREATPULSE_API_KEY'])`,
      },
    ],
  },
  rest: {
    title: 'REST API Integration',
    sections: [
      {
        heading: '01 // ENDPOINT',
        code: 'POST /api/v1/ingest',
      },
      {
        heading: '02 // HEADERS',
        code: `X-API-Key: tp_live_your_key_here
Content-Type: application/json`,
      },
      {
        heading: '03 // REQUEST BODY',
        description: 'Send an array of events for threat analysis.',
        code: `{
  "events": [{
    "timestamp": "2024-01-15T10:30:00Z",
    "user": "john@example.com",
    "ip": "192.168.1.100",
    "action": "login",
    "status": "success",
    "resource": "/api/auth"
  }]
}`,
      },
    ],
  },
};

function CodeBlock({ code }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(code);
    } catch {
      const ta = document.createElement('textarea');
      ta.value = code;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
    }
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // Simple keyword highlighting
  const KEYWORDS = [
    'const', 'require', 'import', 'from', 'new', 'process', 'os',
    'POST', 'GET', 'PUT', 'DELETE', 'PATCH',
    'pip', 'npm', 'install',
    'app', 'use',
  ];

  const STRING_RE = /('(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*")/g;
  const COMMENT_RE = /(\/\/.*$|#.*$)/gm;

  const highlightLine = (line) => {
    const parts = [];
    let lastIndex = 0;

    // Find comments first
    const commentMatch = line.match(COMMENT_RE);
    let mainPart = line;
    let commentPart = null;
    if (commentMatch) {
      const idx = line.indexOf(commentMatch[0]);
      mainPart = line.slice(0, idx);
      commentPart = commentMatch[0];
    }

    // Process main part: highlight strings first, then keywords
    const segments = mainPart.split(STRING_RE);
    segments.forEach((seg, i) => {
      if (seg.match(STRING_RE)) {
        // String literal
        parts.push(<span key={`s${i}`} style={{ color: '#ffb800' }}>{seg}</span>);
      } else {
        // Highlight keywords within this segment
        const wordRe = new RegExp(`\\b(${KEYWORDS.join('|')})\\b`, 'g');
        let wLast = 0;
        let match;
        const subParts = [];
        while ((match = wordRe.exec(seg)) !== null) {
          if (match.index > wLast) {
            subParts.push(<span key={`w${i}-${wLast}`}>{seg.slice(wLast, match.index)}</span>);
          }
          subParts.push(<span key={`w${i}-${match.index}`} style={{ color: '#00e5b0' }}>{match[0]}</span>);
          wLast = match.index + match[0].length;
        }
        if (wLast < seg.length) {
          subParts.push(<span key={`w${i}-end`}>{seg.slice(wLast)}</span>);
        }
        parts.push(...subParts);
      }
    });

    if (commentPart) {
      parts.push(<span key="comment" style={{ color: '#2e5570' }}>{commentPart}</span>);
    }

    return parts;
  };

  const lines = code.split('\n');

  return (
    <div style={{ position: 'relative', marginBottom: 16 }}>
      <pre style={{
        fontFamily: 'IBM Plex Mono, monospace', fontSize: 12, lineHeight: 1.8,
        color: '#c8dce6', background: '#060e14',
        border: '1px solid rgba(0,229,176,0.1)', borderRadius: 8,
        padding: '16px 20px', margin: 0, overflowX: 'auto',
        whiteSpace: 'pre',
      }}>
        {lines.map((line, i) => (
          <div key={i}>{highlightLine(line)}</div>
        ))}
      </pre>
      <button onClick={handleCopy} style={{
        position: 'absolute', top: 10, right: 10,
        fontFamily: 'IBM Plex Mono, monospace', fontSize: 10,
        padding: '5px 12px', borderRadius: 4, border: '1px solid rgba(0,229,176,0.2)',
        cursor: 'pointer', background: copied ? 'rgba(0,229,176,0.15)' : 'rgba(0,229,176,0.06)',
        color: copied ? '#00e5b0' : '#6e9ab5',
        letterSpacing: '0.08em', textTransform: 'uppercase', transition: 'all 0.2s',
      }}>
        {copied ? 'COPIED' : 'COPY'}
      </button>
    </div>
  );
}

export default function IntegrationGuidePage() {
  const [activeTab, setActiveTab] = useState('nodejs');
  const content = TAB_CONTENT[activeTab];

  return (
    <div className="page-enter">
      {/* Header */}
      <div style={{ marginBottom: 28 }}>
        <div style={{ fontFamily: 'Syne Mono, monospace', fontSize: 22, color: '#00e5b0', textShadow: '0 0 24px rgba(0,255,200,0.35)', letterSpacing: 2 }}>
          INTEGRATION GUIDE
        </div>
        <div style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 10, color: '#2e5570', letterSpacing: 4, textTransform: 'uppercase', marginTop: 4 }}>
          Connect your applications to ThreatPulse
        </div>
      </div>

      {/* Tab bar */}
      <div style={{
        display: 'flex', gap: 4, marginBottom: 28,
        borderBottom: '1px solid rgba(0,229,176,0.1)', paddingBottom: 0,
      }}>
        {TABS.map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            style={{
              fontFamily: 'IBM Plex Mono, monospace', fontSize: 12,
              padding: '10px 24px', cursor: 'pointer',
              border: 'none', borderBottom: activeTab === tab.id ? '2px solid #00e5b0' : '2px solid transparent',
              background: activeTab === tab.id ? 'rgba(0,229,176,0.06)' : 'transparent',
              color: activeTab === tab.id ? '#00e5b0' : '#2e5570',
              letterSpacing: '0.1em', textTransform: 'uppercase',
              transition: 'all 0.2s', borderRadius: '6px 6px 0 0',
            }}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      <div key={activeTab} style={{ animation: 'fadeIn 0.3s ease' }}>
        <div style={{
          fontFamily: 'Syne Mono, monospace', fontSize: 16, color: '#e8f4f8',
          marginBottom: 24, letterSpacing: '0.05em',
        }}>
          {content.title}
        </div>

        {content.sections.map((section, i) => (
          <div key={i} style={{ marginBottom: 28 }}>
            <div style={{
              fontFamily: 'IBM Plex Mono, monospace', fontSize: 11,
              color: '#00e5b0', letterSpacing: '0.12em', textTransform: 'uppercase',
              marginBottom: 10, opacity: 0.8,
            }}>
              {section.heading}
            </div>
            {section.description && (
              <div style={{
                fontFamily: 'IBM Plex Mono, monospace', fontSize: 12,
                color: '#6e9ab5', marginBottom: 10, lineHeight: 1.6,
              }}>
                {section.description}
              </div>
            )}
            <CodeBlock code={section.code} />
          </div>
        ))}
      </div>

      {/* Footer note */}
      <div style={{
        marginTop: 40, padding: '16px 20px',
        background: 'rgba(0,229,176,0.04)', border: '1px solid rgba(0,229,176,0.1)',
        borderRadius: 8,
      }}>
        <div style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 11, color: '#6e9ab5', lineHeight: 1.8 }}>
          <span style={{ color: '#00e5b0', letterSpacing: '0.1em' }}>NOTE:</span> You will need an API key to authenticate requests.
          Generate one from the <span style={{ color: '#00e5b0' }}>API Keys</span> page.
          All API keys follow the format <span style={{ color: '#ffb800' }}>tp_live_*</span> for production
          and <span style={{ color: '#ffb800' }}>tp_test_*</span> for sandbox environments.
        </div>
      </div>
    </div>
  );
}
