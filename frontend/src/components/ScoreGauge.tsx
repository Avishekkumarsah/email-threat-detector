import React from 'react';

interface ScoreGaugeProps {
  score: number;
  size?: number;
  strokeWidth?: number;
  risk?: string | null;
}

export const ScoreGauge: React.FC<ScoreGaugeProps> = ({
  score,
  size = 180,
  strokeWidth = 14,
  risk,
}) => {
  const normalizedScore = Math.max(0, Math.min(100, score || 0));
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (normalizedScore / 100) * circumference;

  let strokeColor = '#10b981'; // safe
  let glowColor = 'rgba(16, 185, 129, 0.3)';

  if (normalizedScore >= 70 || risk === 'Critical Risk' || risk === 'Likely Phishing' || risk === 'Dangerous') {
    strokeColor = '#ef4444';
    glowColor = 'rgba(239, 68, 68, 0.4)';
  } else if (normalizedScore >= 45 || risk === 'High Risk') {
    strokeColor = '#f97316';
    glowColor = 'rgba(249, 115, 22, 0.4)';
  } else if (normalizedScore >= 20 || risk === 'Medium Risk' || risk === 'Suspicious') {
    strokeColor = '#f59e0b';
    glowColor = 'rgba(245, 158, 11, 0.4)';
  }

  return (
    <div style={{ position: 'relative', width: size, height: size, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <svg width={size} height={size} style={{ transform: 'rotate(-90deg)' }}>
        {/* Track */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          stroke="rgba(255, 255, 255, 0.08)"
          strokeWidth={strokeWidth}
          fill="none"
        />
        {/* Animated Fill */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          stroke={strokeColor}
          strokeWidth={strokeWidth}
          fill="none"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          strokeLinecap="round"
          style={{
            transition: 'stroke-dashoffset 1s ease-in-out, stroke 0.5s ease',
            filter: `drop-shadow(0 0 10px ${glowColor})`,
          }}
        />
      </svg>
      {/* Center Score Label */}
      <div style={{ position: 'absolute', textAlign: 'center' }}>
        <div style={{ fontSize: size * 0.26, fontWeight: 800, fontFamily: 'JetBrains Mono', color: strokeColor, lineHeight: 1 }}>
          {normalizedScore}
        </div>
        <div style={{ fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.1em', color: '#94a3b8', marginTop: 4 }}>
          Threat Score
        </div>
      </div>
    </div>
  );
};
