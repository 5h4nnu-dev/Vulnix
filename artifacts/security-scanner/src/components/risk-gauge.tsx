interface RiskGaugeProps {
  score: number;
  level: 'critical' | 'high' | 'medium' | 'low' | 'info' | null;
  size?: number;
}

export function RiskGauge({ score, level, size = 120 }: RiskGaugeProps) {
  const strokeWidth = size * 0.1;
  const radius = (size - strokeWidth) / 2;
  const circumference = radius * 2 * Math.PI;
  // 0-100 to stroke-dashoffset (100 = 0 offset, 0 = full circumference offset)
  const offset = circumference - (score / 100) * circumference;

  let colorClass = "text-gray-500";
  if (level === 'critical') colorClass = "text-destructive";
  else if (level === 'high') colorClass = "text-orange-500";
  else if (level === 'medium') colorClass = "text-amber-500";
  else if (level === 'low') colorClass = "text-blue-500";

  return (
    <div className="relative flex items-center justify-center" style={{ width: size, height: size }}>
      {/* Background track */}
      <svg width={size} height={size} className="transform -rotate-90">
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          stroke="currentColor"
          strokeWidth={strokeWidth}
          fill="transparent"
          className="text-muted/30"
        />
        {/* Progress track */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          stroke="currentColor"
          strokeWidth={strokeWidth}
          fill="transparent"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          className={`transition-all duration-1000 ease-out ${colorClass}`}
          strokeLinecap="round"
        />
      </svg>
      {/* Center text */}
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className={`text-3xl font-mono font-bold ${colorClass}`}>
          {score}
        </span>
        <span className="text-[10px] font-mono text-muted-foreground tracking-widest uppercase">
          Risk
        </span>
      </div>
    </div>
  );
}
