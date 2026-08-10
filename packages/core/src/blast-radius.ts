import type { Finding, ProposedAction } from "./types.js";

export type BlastClass = "shell" | "network" | "payment" | "destructive";

export interface BlastLimits {
  /** Max events per window per class */
  shell: number;
  network: number;
  payment: number;
  destructive: number;
  window_ms: number;
}

export const DEFAULT_BLAST_LIMITS: BlastLimits = {
  shell: 10,
  network: 60,
  payment: 3,
  destructive: 5,
  window_ms: 60 * 60 * 1000,
};

export function classifyAction(action: ProposedAction): BlastClass | null {
  const tool = `${action.tool} ${action.type}`.toLowerCase();
  if (/pay|transfer|wire|checkout|payment/.test(tool)) return "payment";
  if (/shell|bash|exec|run_command/.test(tool)) return "shell";
  if (/delete|rm\b|drop\s+table|admin_iam/.test(tool)) return "destructive";
  if (/http|fetch|email|webhook|browser|upload|mcp\./.test(tool)) return "network";
  if (action.destination) return "network";
  return null;
}

/** In-memory sliding-window counter (API may wrap with persistence). */
export class BlastRadiusTracker {
  private events = new Map<string, number[]>();
  private limits: BlastLimits;

  constructor(limits: Partial<BlastLimits> = {}) {
    this.limits = { ...DEFAULT_BLAST_LIMITS, ...limits };
  }

  private key(agentId: string, cls: BlastClass): string {
    return `${agentId}::${cls}`;
  }

  private prune(ts: number[], now: number): number[] {
    const cutoff = now - this.limits.window_ms;
    return ts.filter((t) => t >= cutoff);
  }

  /** Record and return findings if over limit. Call only when action would proceed. */
  check(agentId: string, action: ProposedAction, record = true): Finding[] {
    const cls = classifyAction(action);
    if (!cls) return [];
    const now = Date.now();
    const k = this.key(agentId, cls);
    let ts = this.prune(this.events.get(k) ?? [], now);
    const limit = this.limits[cls];
    if (ts.length >= limit) {
      return [
        {
          detector: "blast_radius",
          severity: "critical",
          code: "blast.limit_exceeded",
          message: `Agent exceeded ${cls} blast-radius cap (${limit} per window)`,
          evidence: `${cls}:${ts.length}/${limit}`,
        },
      ];
    }
    if (record) {
      ts.push(now);
      this.events.set(k, ts);
    }
    return [];
  }

  snapshot(agentId: string): Record<BlastClass, number> {
    const now = Date.now();
    const out = { shell: 0, network: 0, payment: 0, destructive: 0 };
    for (const cls of Object.keys(out) as BlastClass[]) {
      out[cls] = this.prune(this.events.get(this.key(agentId, cls)) ?? [], now).length;
    }
    return out;
  }
}
