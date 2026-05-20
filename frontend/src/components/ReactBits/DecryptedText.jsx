import React, { useState, useEffect, useRef } from 'react';
import './DecryptedText.css';

const DEFAULT_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+{}:"<>?,./;\'[]\\=-~';

export default function DecryptedText({
  text = '',
  speed = 50,
  maxIterations = 10,
  sequential = true,
  className = '',
  animateOn = 'hover', // 'hover' or 'mount'
  style = {},
  ...props
}) {
  const [displayedText, setDisplayedText] = useState('');
  const [isHovered, setIsHovered] = useState(false);
  const [isDecrypting, setIsDecrypting] = useState(false);
  const animationRef = useRef(null);

  // Initialize text with scrambled characters or keep empty
  useEffect(() => {
    setDisplayedText(text);
  }, [text]);

  const startDecryption = () => {
    if (isDecrypting) return;
    setIsDecrypting(true);
    
    let currentIteration = 0;
    const targetLength = text.length;
    
    if (animationRef.current) clearInterval(animationRef.current);

    animationRef.current = setInterval(() => {
      currentIteration++;

      const scrambled = text.split('').map((char, index) => {
        if (char === ' ') return ' ';
        
        // If sequential, resolve characters from left to right
        if (sequential) {
          const resolvedThreshold = Math.floor((currentIteration / maxIterations) * targetLength);
          if (index < resolvedThreshold) {
            return char;
          }
        } else {
          // If not sequential, check random chance to resolve
          if (currentIteration >= maxIterations || Math.random() < currentIteration / maxIterations) {
            return char;
          }
        }

        // Return a random character
        const randomIndex = Math.floor(Math.random() * DEFAULT_CHARS.length);
        return DEFAULT_CHARS[randomIndex];
      });

      setDisplayedText(scrambled.join(''));

      if (currentIteration >= maxIterations) {
        setDisplayedText(text);
        setIsDecrypting(false);
        clearInterval(animationRef.current);
      }
    }, speed);
  };

  useEffect(() => {
    if (animateOn === 'mount') {
      startDecryption();
    }
    return () => {
      if (animationRef.current) clearInterval(animationRef.current);
    };
  }, [animateOn, text]);

  const handleMouseEnter = () => {
    setIsHovered(true);
    if (animateOn === 'hover') {
      startDecryption();
    }
  };

  const handleMouseLeave = () => {
    setIsHovered(false);
  };

  return (
    <span
      className={`decrypted-text ${className}`}
      onMouseEnter={handleMouseEnter}
      onMouseLeave={handleMouseLeave}
      style={{
        fontFamily: 'monospace',
        letterSpacing: '0.05em',
        transition: 'color 0.3s ease',
        ...style,
      }}
      {...props}
    >
      {displayedText}
    </span>
  );
}
