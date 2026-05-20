import React, { useRef, useState } from 'react';
import './SpotlightCard.css';

export default function SpotlightCard({
  children,
  className = '',
  spotlightColor = 'rgba(255, 255, 255, 0.08)',
  borderColor = 'rgba(255, 255, 255, 0.15)',
  spotlightSize = '350px',
  style = {},
  ...props
}) {
  const cardRef = useRef(null);
  const [coords, setCoords] = useState({ x: -1000, y: -1000 });
  const [opacity, setOpacity] = useState(0);

  const handleMouseMove = (e) => {
    if (!cardRef.current) return;
    const rect = cardRef.current.getBoundingClientRect();
    setCoords({
      x: e.clientX - rect.left,
      y: e.clientY - rect.top,
    });
  };

  const handleMouseEnter = () => {
    setOpacity(1);
  };

  const handleMouseLeave = () => {
    setOpacity(0);
    setCoords({ x: -1000, y: -1000 });
  };

  return (
    <div
      ref={cardRef}
      onMouseMove={handleMouseMove}
      onMouseEnter={handleMouseEnter}
      onMouseLeave={handleMouseLeave}
      className={`spotlight-card ${className}`}
      style={{
        position: 'relative',
        borderRadius: '16px',
        overflow: 'hidden',
        background: '#050505',
        border: `1px solid rgba(255, 255, 255, 0.05)`,
        transition: 'border-color 0.3s ease',
        ...style,
      }}
      {...props}
    >
      {/* Dynamic Border Glow Highlight */}
      <div
        className="spotlight-border-glow"
        style={{
          position: 'absolute',
          inset: 0,
          opacity,
          pointerEvents: 'none',
          zIndex: 1,
          borderRadius: '16px',
          padding: '1px',
          WebkitMask: 'linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0)',
          WebkitMaskComposite: 'xor',
          maskComposite: 'exclude',
          background: `radial-gradient(${spotlightSize} circle at ${coords.x}px ${coords.y}px, ${borderColor}, transparent 80%)`,
          transition: 'opacity 0.3s ease',
        }}
      />

      {/* Dynamic Background Spotlight Radial Glow */}
      <div
        className="spotlight-bg-glow"
        style={{
          position: 'absolute',
          inset: 0,
          opacity,
          pointerEvents: 'none',
          zIndex: 0,
          background: `radial-gradient(${spotlightSize} circle at ${coords.x}px ${coords.y}px, ${spotlightColor}, transparent 80%)`,
          transition: 'opacity 0.3s ease',
        }}
      />

      {/* Card Content Wrapper */}
      <div className="spotlight-card-content" style={{ position: 'relative', zIndex: 2, height: '100%' }}>
        {children}
      </div>
    </div>
  );
}
