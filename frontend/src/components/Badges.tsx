
interface SeverityBadgeProps {
  severity: string;
  className?: string;
}

const SEVERITY_CLASS: Record<string, string> = {
  CRITICAL: 'badge-critical',
  HIGH: 'badge-high',
  MEDIUM: 'badge-medium',
  LOW: 'badge-low',
  INFORMATIONAL: 'badge-uncertain',
};

export function SeverityBadge({ severity, className = '' }: SeverityBadgeProps) {
  const cls = SEVERITY_CLASS[severity?.toUpperCase()] || 'badge-uncertain';
  return (
    <span className={`badge ${cls} ${className}`} aria-label={`Severity: ${severity}`}>
      {severity}
    </span>
  );
}

interface PriorityBadgeProps {
  label: string;
  score?: number;
}

const PRIORITY_CLASS: Record<string, string> = {
  CRITICAL: 'badge-critical',
  HIGH: 'badge-high',
  MEDIUM: 'badge-medium',
  LOW: 'badge-low',
  UNCERTAIN: 'badge-uncertain',
};

export function PriorityBadge({ label, score }: PriorityBadgeProps) {
  const cls = PRIORITY_CLASS[label?.toUpperCase()] || 'badge-uncertain';
  return (
    <span className={`badge ${cls}`}>
      {label}
      {score !== undefined && ` · ${score}/100`}
    </span>
  );
}

interface CriticalityBadgeProps {
  criticality: string;
}

export function CriticalityBadge({ criticality }: CriticalityBadgeProps) {
  const cls = SEVERITY_CLASS[criticality?.toUpperCase()] || 'badge-uncertain';
  return <span className={`badge ${cls}`}>{criticality}</span>;
}

export function SyntheticBadge({ label = 'SYNTHETIC BENCHMARK' }: { label?: string }) {
  return (
    <span
      className="badge"
      style={{
        background: '#F3E8FF',
        color: '#6B21A8',
        borderColor: '#D8B4FE',
        fontWeight: 600,
        fontSize: '10px',
        letterSpacing: '0.4px',
      }}
      title="Synthetic benchmark dataset entity — Not a verified real-world vulnerability"
    >
      {label}
    </span>
  );
}

