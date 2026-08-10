import type { Finding, ProposedAction, TrajectoryStep } from "./types.js";

export interface TrajectoryPattern {
  id: string;
  name: string;
  description: string;
  severity: Finding["severity"];
  /** Ordered tool-name regexes that must appear in sequence (not necessarily contiguous). */
  sequence: RegExp[];
  min_steps?: number;
}

export const DEFAULT_TRAJECTORY_PATTERNS: TrajectoryPattern[] = [
  {
    id: "traj.recon_then_exfil",
    name: "Recon then exfiltration",
    description: "Read/list sensitive data then send outbound",
    severity: "critical",
    sequence: [/read|list|get|query|cat|file_read/i, /http|fetch|email|post|upload|webhook/i],
  },
  {
    id: "traj.cred_harvest",
    name: "Credential harvest chain",
    description: "Access env/secrets then network",
    severity: "critical",
    sequence: [/env|secret|vault|credential|config/i, /http|fetch|curl|webhook|email/i],
  },
  {
    id: "traj.priv_escalation",
    name: "Permission probing then privileged tool",
    description: "Enumerate permissions then high-impact action",
    severity: "high",
    sequence: [/whoami|permissions|scopes|role/i, /admin|iam|policy|shell|exec|delete/i],
  },
  {
    id: "traj.payment_burst",
    name: "Repeated payment attempts",
    description: "Multiple payment/transfer tools in one session",
    severity: "high",
    sequence: [/pay|transfer|wire|checkout/i, /pay|transfer|wire|checkout/i],
    min_steps: 2,
  },
  {
    id: "traj.download_exec",
    name: "Download then execute",
    description: "Fetch remote content then run shell/code",
    severity: "critical",
    sequence: [/http|fetch|download|browser/i, /shell|bash|exec|run_command/i],
  },
];

function toolsInOrder(history: TrajectoryStep[], proposed?: ProposedAction): string[] {
  const tools = history.map((h) => actionSignature(h.action));
  if (proposed) tools.push(actionSignature(proposed));
  return tools;
}

/** Tool name plus destination/param cues so aliases still match sequences. */
function actionSignature(action: ProposedAction): string {
  const parts = [action.tool, action.type];
  if (action.destination) parts.push(action.destination);
  const params = action.parameters ?? {};
  for (const [k, v] of Object.entries(params)) {
    if (typeof v === "string" && /url|path|to|command|cmd|body|host/i.test(k)) {
      parts.push(`${k}:${v.slice(0, 80)}`);
    }
  }
  return parts.join(" ");
}

export function detectTrajectory(
  history: TrajectoryStep[],
  proposed?: ProposedAction,
  patterns: TrajectoryPattern[] = DEFAULT_TRAJECTORY_PATTERNS,
): Finding[] {
  const tools = toolsInOrder(history, proposed);
  const findings: Finding[] = [];

  for (const pattern of patterns) {
    let idx = 0;
    for (const tool of tools) {
      if (pattern.sequence[idx]?.test(tool)) {
        idx += 1;
        if (idx >= pattern.sequence.length) break;
      }
    }
    if (idx >= pattern.sequence.length) {
      findings.push({
        detector: "trajectory",
        severity: pattern.severity,
        code: pattern.id,
        message: `${pattern.name}: ${pattern.description}`,
        evidence: tools.join(" → "),
      });
    }
  }

  // Velocity: many distinct high-risk tools quickly
  const risky = tools.filter((t) => /shell|exec|http|email|pay|delete|admin/i.test(t));
  if (risky.length >= 4) {
    findings.push({
      detector: "trajectory",
      severity: "high",
      code: "traj.high_velocity_risk",
      message: `Session includes ${risky.length} elevated-risk tool uses`,
      evidence: risky.join(", "),
    });
  }

  return findings;
}
