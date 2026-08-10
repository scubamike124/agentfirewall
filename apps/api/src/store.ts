import fs from "fs";
import path from "path";
import type { AuditRecord, PolicyConfig, ProposedAction, TrajectoryStep } from "@agentfirewall/core";
import { DEFAULT_POLICY, mergePolicyWithDefaults } from "@agentfirewall/core";

const dataDir = process.env.AGENTFIREWALL_DATA ?? path.join(process.cwd(), ".data");

function ensure() {
  fs.mkdirSync(dataDir, { recursive: true });
}

export function loadPolicy(): PolicyConfig {
  ensure();
  const p = path.join(dataDir, "policy.json");
  if (!fs.existsSync(p)) {
    fs.writeFileSync(p, JSON.stringify(DEFAULT_POLICY, null, 2));
    return structuredClone(DEFAULT_POLICY);
  }
  const stored = JSON.parse(fs.readFileSync(p, "utf8")) as PolicyConfig;
  const merged = mergePolicyWithDefaults(stored, DEFAULT_POLICY);
  // Persist merged defaults so production volumes pick up new block codes after deploy.
  try {
    if (JSON.stringify(merged) !== JSON.stringify(stored)) {
      fs.writeFileSync(p, JSON.stringify(merged, null, 2));
    }
  } catch {
    /* read-only volume edge case — still return merged in-memory */
  }
  return merged;
}

export function savePolicy(policy: PolicyConfig): void {
  ensure();
  fs.writeFileSync(path.join(dataDir, "policy.json"), JSON.stringify(policy, null, 2));
}

export function appendAudit(record: AuditRecord): void {
  ensure();
  const p = path.join(dataDir, "audit.jsonl");
  fs.appendFileSync(p, `${JSON.stringify(record)}\n`);
}

export function listAudit(limit = 100): AuditRecord[] {
  ensure();
  const p = path.join(dataDir, "audit.jsonl");
  if (!fs.existsSync(p)) return [];
  const lines = fs.readFileSync(p, "utf8").trim().split("\n").filter(Boolean);
  return lines
    .slice(-limit)
    .map((l) => JSON.parse(l) as AuditRecord)
    .reverse();
}

export interface ApprovalRecord {
  id: string;
  evaluation_id: string;
  agent_id: string;
  status: "pending" | "approved" | "denied" | "expired" | "consumed";
  created_at: string;
  resolved_at?: string;
  expires_at?: string;
  note?: string;
  action_summary: string;
  /** Bound action fingerprint */
  action_hash?: string;
  /** Serialized ProposedAction for resume verification */
  action?: import("@agentfirewall/core").ProposedAction;
  destination?: string;
  /** SHA-256 of one-time resume token */
  resume_token_hash?: string;
  /** Who resolved (API key label / break-glass id) */
  resolved_by?: string;
  consumed_at?: string;
}

export function saveApproval(a: ApprovalRecord): void {
  ensure();
  const p = path.join(dataDir, "approvals.json");
  const all = listApprovals();
  const idx = all.findIndex((x) => x.id === a.id);
  if (idx >= 0) all[idx] = a;
  else all.unshift(a);
  fs.writeFileSync(p, JSON.stringify(all, null, 2));
}

export function listApprovals(): ApprovalRecord[] {
  ensure();
  const p = path.join(dataDir, "approvals.json");
  if (!fs.existsSync(p)) return [];
  return JSON.parse(fs.readFileSync(p, "utf8")) as ApprovalRecord[];
}

export function getApproval(id: string): ApprovalRecord | undefined {
  return listApprovals().find((a) => a.id === id);
}

export interface WebhookConfig {
  url: string;
  events: string[];
  secret?: string;
}

export function loadWebhooks(): WebhookConfig[] {
  ensure();
  const p = path.join(dataDir, "webhooks.json");
  if (!fs.existsSync(p)) {
    fs.writeFileSync(p, "[]");
    return [];
  }
  return JSON.parse(fs.readFileSync(p, "utf8")) as WebhookConfig[];
}

export function saveWebhooks(hooks: WebhookConfig[]): void {
  ensure();
  fs.writeFileSync(path.join(dataDir, "webhooks.json"), JSON.stringify(hooks, null, 2));
}

export async function dispatchWebhooks(
  event: string,
  payload: Record<string, unknown>,
): Promise<void> {
  const hooks = loadWebhooks().filter((h) => h.events.includes(event) || h.events.includes("*"));
  await Promise.allSettled(
    hooks.map(async (h) => {
      await fetch(h.url, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          ...(h.secret ? { "x-agentfirewall-secret": h.secret } : {}),
        },
        body: JSON.stringify({ event, payload, at: new Date().toISOString() }),
      });
    }),
  );
}

/** Server-side session trajectory — differentiator that works without client-side history. */
export interface SessionState {
  session_id: string;
  agent_id: string;
  steps: TrajectoryStep[];
  updated_at: string;
}

function sessionsPath(): string {
  return path.join(dataDir, "sessions.json");
}

function loadSessions(): Record<string, SessionState> {
  ensure();
  const p = sessionsPath();
  if (!fs.existsSync(p)) return {};
  try {
    return JSON.parse(fs.readFileSync(p, "utf8")) as Record<string, SessionState>;
  } catch {
    return {};
  }
}

function saveSessions(all: Record<string, SessionState>): void {
  ensure();
  fs.writeFileSync(sessionsPath(), JSON.stringify(all, null, 2));
}

function sessionKey(agentId: string, sessionId: string): string {
  return `${agentId}::${sessionId}`;
}

export function getSession(agentId: string, sessionId: string): SessionState | undefined {
  return loadSessions()[sessionKey(agentId, sessionId)];
}

export function listSessionActions(agentId: string, sessionId: string): ProposedAction[] {
  return (getSession(agentId, sessionId)?.steps ?? []).map((s) => s.action);
}

export function appendSessionStep(
  agentId: string,
  sessionId: string,
  step: TrajectoryStep,
  maxSteps = 50,
): SessionState {
  const all = loadSessions();
  const key = sessionKey(agentId, sessionId);
  const existing = all[key] ?? {
    session_id: sessionId,
    agent_id: agentId,
    steps: [],
    updated_at: new Date().toISOString(),
  };
  existing.steps.push(step);
  if (existing.steps.length > maxSteps) {
    existing.steps = existing.steps.slice(-maxSteps);
  }
  existing.updated_at = new Date().toISOString();
  all[key] = existing;
  saveSessions(all);
  return existing;
}

export function clearSession(agentId: string, sessionId: string): void {
  const all = loadSessions();
  delete all[sessionKey(agentId, sessionId)];
  saveSessions(all);
}

export function listAllSessions(): SessionState[] {
  return Object.values(loadSessions()).sort((a, b) => b.updated_at.localeCompare(a.updated_at));
}

export function pruneAudit(retentionDays: number): { removed: number; kept: number } {
  ensure();
  const p = path.join(dataDir, "audit.jsonl");
  if (!fs.existsSync(p)) return { removed: 0, kept: 0 };
  const cutoff = Date.now() - retentionDays * 24 * 60 * 60 * 1000;
  const lines = fs.readFileSync(p, "utf8").trim().split("\n").filter(Boolean);
  const kept: string[] = [];
  let removed = 0;
  for (const line of lines) {
    try {
      const rec = JSON.parse(line) as AuditRecord;
      if (new Date(rec.timestamp).getTime() >= cutoff) kept.push(line);
      else removed += 1;
    } catch {
      removed += 1;
    }
  }
  fs.writeFileSync(p, kept.length ? `${kept.join("\n")}\n` : "");
  return { removed, kept: kept.length };
}

export function exportAuditSiem(limit = 1000): Record<string, unknown>[] {
  return listAudit(limit).map((e) => ({
    timestamp: e.timestamp,
    event_type: "agentfirewall.security_decision",
    vendor: "AgentFirewall",
    product: "AgentFirewall",
    agent_id: e.agent_id,
    decision: e.decision,
    risk_score: e.risk_score,
    tool: e.tool,
    action_type: e.action_type,
    destination: e.destination,
    evaluation_id: e.id,
    session_id: e.session_id,
    findings: e.findings.map((f) => f.code),
    explanation: e.explanation,
  }));
}

export function exportAuditCsv(limit = 1000): string {
  const rows = listAudit(limit);
  const header = [
    "timestamp",
    "evaluation_id",
    "agent_id",
    "decision",
    "risk_score",
    "tool",
    "action_type",
    "destination",
    "finding_codes",
    "explanation",
  ];
  const escape = (v: unknown) => `"${String(v ?? "").replace(/"/g, '""')}"`;
  const lines = [header.join(",")];
  for (const e of rows) {
    lines.push(
      [
        e.timestamp,
        e.id,
        e.agent_id,
        e.decision,
        e.risk_score,
        e.tool,
        e.action_type,
        e.destination,
        e.findings.map((f) => f.code).join("|"),
        e.explanation,
      ]
        .map(escape)
        .join(","),
    );
  }
  return lines.join("\n");
}

interface UsageDay {
  day: string;
  evaluations: number;
}

export function bumpEvaluationUsage(): number {
  ensure();
  const p = path.join(dataDir, "usage.json");
  const day = new Date().toISOString().slice(0, 10);
  let usage: UsageDay = { day, evaluations: 0 };
  try {
    if (fs.existsSync(p)) usage = JSON.parse(fs.readFileSync(p, "utf8")) as UsageDay;
  } catch {
    /* ignore */
  }
  if (usage.day !== day) usage = { day, evaluations: 0 };
  usage.evaluations += 1;
  fs.writeFileSync(p, JSON.stringify(usage, null, 2));
  return usage.evaluations;
}

export function getEvaluationUsage(): UsageDay {
  ensure();
  const p = path.join(dataDir, "usage.json");
  const day = new Date().toISOString().slice(0, 10);
  try {
    if (fs.existsSync(p)) {
      const usage = JSON.parse(fs.readFileSync(p, "utf8")) as UsageDay;
      if (usage.day === day) return usage;
    }
  } catch {
    /* ignore */
  }
  return { day, evaluations: 0 };
}

export function dataDirPath(): string {
  return dataDir;
}

export function loadMcpTrust(): import("@agentfirewall/core").McpTrustRegistry {
  ensure();
  const p = path.join(dataDir, "mcp-trust.json");
  if (!fs.existsSync(p)) {
    const empty = { servers: [] };
    fs.writeFileSync(p, JSON.stringify(empty, null, 2));
    return empty;
  }
  return JSON.parse(fs.readFileSync(p, "utf8")) as import("@agentfirewall/core").McpTrustRegistry;
}

export function saveMcpTrust(registry: import("@agentfirewall/core").McpTrustRegistry): void {
  ensure();
  fs.writeFileSync(path.join(dataDir, "mcp-trust.json"), JSON.stringify(registry, null, 2));
}

/** Expire pending approvals past expires_at. */
export function expireStaleApprovals(): number {
  const all = listApprovals();
  const now = Date.now();
  let n = 0;
  for (const a of all) {
    if (a.status === "pending" && a.expires_at && new Date(a.expires_at).getTime() < now) {
      a.status = "expired";
      a.resolved_at = new Date().toISOString();
      a.note = a.note ?? "Timed out — denied by default";
      n += 1;
    }
  }
  if (n) {
    fs.writeFileSync(path.join(dataDir, "approvals.json"), JSON.stringify(all, null, 2));
  }
  return n;
}
