import { AlertTriangle, CheckCircle2, Clock, ShieldAlert, ShieldCheck, ShieldOff } from 'lucide-react';
import type { IncidentSeverity, SecurityDecision, TrustStatus } from '../types/toolseal';

export function DecisionIndicator({ decision }: { decision: SecurityDecision }) {
  if (decision === 'ALLOW') {
    return (
      <span className="inline-flex items-center gap-1.5 text-xs font-mono font-semibold text-[#1B6B44] whitespace-nowrap">
        <CheckCircle2 className="w-3.5 h-3.5 shrink-0" />
        <span>ALLOW</span>
      </span>
    );
  }
  if (decision === 'REVIEW') {
    return (
      <span className="inline-flex items-center gap-1.5 text-xs font-mono font-semibold text-[#A16207] whitespace-nowrap">
        <Clock className="w-3.5 h-3.5 shrink-0" />
        <span>REVIEW</span>
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1.5 text-xs font-mono font-semibold text-[#B91C1C] whitespace-nowrap">
      <ShieldOff className="w-3.5 h-3.5 shrink-0" />
      <span>BLOCK</span>
    </span>
  );
}

export function TrustIndicator({ status }: { status: TrustStatus }) {
  if (status === 'trusted') {
    return (
      <span className="inline-flex items-center gap-1.5 text-xs font-mono font-medium text-[#1B6B44] whitespace-nowrap">
        <ShieldCheck className="w-3.5 h-3.5 shrink-0" />
        <span>Trusted DNA</span>
      </span>
    );
  }
  if (status === 'modified') {
    return (
      <span className="inline-flex items-center gap-1.5 text-xs font-mono font-medium text-[#A16207] whitespace-nowrap">
        <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
        <span>Modified</span>
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1.5 text-xs font-mono font-medium text-[#B91C1C] whitespace-nowrap">
      <ShieldAlert className="w-3.5 h-3.5 shrink-0" />
      <span>Untrusted</span>
    </span>
  );
}

export function SeverityText({ severity }: { severity: IncidentSeverity }) {
  const color =
    severity === 'critical'
      ? 'text-[#B91C1C]'
      : severity === 'high'
      ? 'text-[#C2410C]'
      : severity === 'medium'
      ? 'text-[#A16207]'
      : 'text-[#1B6B44]';

  return (
    <span className={`text-xs font-mono font-semibold uppercase tracking-wide whitespace-nowrap ${color}`}>
      {severity}
    </span>
  );
}

export function RiskScoreValue({ score }: { score: number }) {
  const color =
    score > 70 ? 'text-[#B91C1C]' : score > 30 ? 'text-[#A16207]' : 'text-[#1B6B44]';

  return (
    <span className={`font-mono text-xs font-semibold tabular-nums whitespace-nowrap ${color}`}>
      {score}/100
    </span>
  );
}
