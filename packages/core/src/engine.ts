import { randomBytes } from "crypto";
import type {
  AuditRecord,
  Decision,
  EvaluateRequest,
  EvaluateResponse,
  Finding,
  PolicyConfig,
  TrajectoryEvaluateRequest,
  TrajectoryEvaluateResponse,
} from "./types.js";
import { detectSecrets, redactDeep } from "./detectors/secrets.js";
import { detectPromptInjection } from "./detectors/prompt-injection.js";
import { inspectToolCall } from "./detectors/tool-inspect.js";
import { inspectMcpDescriptors } from "./detectors/mcp.js";
import { inspectUntrustedGate } from "./detectors/untrusted-gate.js";
import { detectTrajectory } from "./trajectory.js";
import { DEFAULT_POLICY, applyPolicies } from "./policy.js";
import { hashAction } from "./action-hash.js";
import { inspectEgress, type EgressMode } from "./egress.js";
import { BlastRadiusTracker, type BlastLimits } from "./blast-radius.js";
import {
  inspectMcpTrust,
  type McpDescriptorInput,
  type McpTrustRegistry,
} from "./mcp-trust.js";

function id(prefix: string): string {
  return `${prefix}_${randomBytes(10).toString("hex")}`;
}

function explain(decision: Decision, findings: Finding[], matchedIds: string[]): string {
  if (findings.length === 0 && decision === "allow") {
    return "No elevated risk findings; default policy allows this action.";
  }
  const top = findings
    .slice()
    .sort((a, b) => severityRank(b.severity) - severityRank(a.severity))
    .slice(0, 3)
    .map((f) => f.message);
  const policyNote = matchedIds.length ? ` Matched policies: ${matchedIds.join(", ")}.` : "";
  if (decision === "block") return `Blocked. ${top.join(" ")}${policyNote}`;
  if (decision === "approval_required") {
    return `Human approval required before execution. ${top.join(" ")}${policyNote}`;
  }
  return `Allowed with findings. ${top.join(" ")}${policyNote}`;
}

function severityRank(s: Finding["severity"]): number {
  return s === "critical" ? 4 : s === "high" ? 3 : s === "medium" ? 2 : 1;
}

export interface FirewallEngineOptions {
  policy?: PolicyConfig;
  onAudit?: (record: AuditRecord) => void | Promise<void>;
  egressMode?: EgressMode;
  blastTracker?: BlastRadiusTracker;
  blastLimits?: Partial<BlastLimits>;
  mcpTrust?: McpTrustRegistry;
  onMcpTrustChange?: (registry: McpTrustRegistry) => void | Promise<void>;
  /** Approval TTL in seconds (default 15m). */
  approvalTtlSeconds?: number;
}

export class FirewallEngine {
  private policy: PolicyConfig;
  private onAudit?: FirewallEngineOptions["onAudit"];
  private egressMode: EgressMode;
  private blast: BlastRadiusTracker;
  private mcpTrust: McpTrustRegistry;
  private onMcpTrustChange?: FirewallEngineOptions["onMcpTrustChange"];
  private approvalTtlSeconds: number;

  constructor(opts: FirewallEngineOptions = {}) {
    this.policy = opts.policy ?? DEFAULT_POLICY;
    this.onAudit = opts.onAudit;
    this.egressMode = opts.egressMode ?? "observe";
    this.blast = opts.blastTracker ?? new BlastRadiusTracker(opts.blastLimits);
    this.mcpTrust = opts.mcpTrust ?? { servers: [] };
    this.onMcpTrustChange = opts.onMcpTrustChange;
    this.approvalTtlSeconds = opts.approvalTtlSeconds ?? 900;
  }

  setPolicy(policy: PolicyConfig): void {
    this.policy = policy;
  }

  getPolicy(): PolicyConfig {
    return this.policy;
  }

  setEgressMode(mode: EgressMode): void {
    this.egressMode = mode;
  }

  setMcpTrust(registry: McpTrustRegistry): void {
    this.mcpTrust = registry;
  }

  getMcpTrust(): McpTrustRegistry {
    return this.mcpTrust;
  }

  getBlastTracker(): BlastRadiusTracker {
    return this.blast;
  }

  async evaluate(req: EvaluateRequest): Promise<EvaluateResponse> {
    const destination = req.destination ?? req.action.destination;
    const untrusted = [
      ...(req.context?.untrusted_content ?? []),
      ...(req.context?.messages ?? []),
    ];
    const mcpRaw = req.context?.mcp_descriptions ?? [];
    const mcpInputs: McpDescriptorInput[] = mcpRaw.map((d) =>
      typeof d === "string" ? d : { server: d.server, name: d.name, description: d.description },
    );
    const mcpTexts = mcpInputs.map((d) =>
      typeof d === "string" ? d : [d.server, d.name, d.description].filter(Boolean).join("\n"),
    );

    const findings: Finding[] = [
      ...detectSecrets([req.action.parameters, untrusted, destination]),
      ...detectPromptInjection([...untrusted, ...mcpTexts]),
      ...inspectMcpDescriptors(mcpRaw),
      ...inspectToolCall(req.action, destination),
      ...inspectUntrustedGate(req.action, untrusted),
      ...inspectEgress({
        destination,
        allowlist: req.agent.egress_allowlist,
        mode: this.egressMode,
      }),
      ...detectTrajectory(
        (req.context?.prior_actions ?? []).map((a) => ({ action: a })),
        req.action,
      ),
    ];

    if (mcpInputs.length) {
      const trust = inspectMcpTrust(mcpInputs, this.mcpTrust);
      findings.push(...trust.findings);
      if (trust.changed) {
        this.mcpTrust = trust.registry;
        await this.onMcpTrustChange?.(trust.registry);
      }
    }

    // Scope attribution
    if (req.agent.scopes?.length) {
      const tool = req.action.tool;
      const scopes = req.agent.scopes;
      const allowed =
        scopes.includes("tools:*") ||
        scopes.includes("*") ||
        scopes.includes(`tool:${tool}`) ||
        (scopes.includes("tools:default") && !/admin|iam|root/i.test(tool));
      if (!allowed) {
        findings.push({
          detector: "identity",
          severity: "high",
          code: "identity.scope_denied",
          message: `Agent scopes do not permit tool "${tool}"`,
        });
      }
    }

    // Blast-radius preview (do not record yet)
    const blastPreview = this.blast.check(req.agent.agent_id, req.action, false);
    findings.push(...blastPreview);

    const { decision, matched, risk_score, risk_level } = applyPolicies(
      this.policy,
      { agent: req.agent, action: req.action, destination },
      findings,
    );

    // Count toward blast budget only for allow / pending-approval (not hard blocks)
    if (decision === "allow" || decision === "approval_required") {
      this.blast.check(req.agent.agent_id, req.action, true);
    }

    const evaluation_id = id("eval");
    const action_hash = hashAction(req.action, destination);
    let approval_id: string | undefined;
    let resume_token: string | undefined;
    let approval_expires_at: string | undefined;
    if (decision === "approval_required") {
      approval_id = id("appr");
      resume_token = `res_${randomBytes(24).toString("base64url")}`;
      approval_expires_at = new Date(Date.now() + this.approvalTtlSeconds * 1000).toISOString();
    }
    const timestamp = new Date().toISOString();
    const explanation = explain(
      decision,
      findings,
      matched.map((m) => m.id),
    );

    const response: EvaluateResponse = {
      evaluation_id,
      decision,
      risk_score,
      risk_level,
      explanation,
      findings,
      policy_ids: matched.map((m) => m.id),
      approval_id,
      action_hash,
      resume_token,
      approval_expires_at,
      agent_id: req.agent.agent_id,
      timestamp,
    };

    await this.emitAudit({
      id: evaluation_id,
      kind: "evaluate",
      agent_id: req.agent.agent_id,
      tool: req.action.tool,
      action_type: req.action.type,
      destination: destination ?? null,
      decision,
      risk_score,
      explanation,
      findings,
      parameters_redacted: redactDeep(req.action.parameters ?? {}) as Record<string, unknown>,
      session_id: req.context?.session_id,
      approval_id,
      timestamp,
    });

    return response;
  }

  async evaluateTrajectory(req: TrajectoryEvaluateRequest): Promise<TrajectoryEvaluateResponse> {
    const findings = detectTrajectory(req.history, req.proposed);
    const proposed = req.proposed ?? req.history.at(-1)?.action;
    const syntheticReq = {
      agent: req.agent,
      action: proposed ?? { type: "trajectory", tool: "trajectory.review" },
    };
    const { decision, matched, risk_score, risk_level } = applyPolicies(
      this.policy,
      syntheticReq,
      findings,
    );

    let finalDecision = decision;
    if (findings.some((f) => f.severity === "critical") && finalDecision === "allow") {
      finalDecision = "approval_required";
    }

    const evaluation_id = id("traj");
    const approval_id = finalDecision === "approval_required" ? id("appr") : undefined;
    const timestamp = new Date().toISOString();
    const explanation = explain(
      finalDecision,
      findings,
      matched.map((m) => m.id),
    );

    const response: TrajectoryEvaluateResponse = {
      evaluation_id,
      decision: finalDecision,
      risk_score,
      risk_level,
      explanation,
      findings,
      pattern_ids: findings.filter((f) => f.detector === "trajectory").map((f) => f.code),
      approval_id,
      agent_id: req.agent.agent_id,
      timestamp,
    };

    await this.emitAudit({
      id: evaluation_id,
      kind: "trajectory",
      agent_id: req.agent.agent_id,
      tool: proposed?.tool,
      action_type: "trajectory",
      destination: proposed?.destination ?? null,
      decision: finalDecision,
      risk_score,
      explanation,
      findings,
      session_id: req.session_id,
      approval_id,
      timestamp,
    });

    return response;
  }

  private async emitAudit(record: AuditRecord): Promise<void> {
    if (this.onAudit) await this.onAudit(record);
  }
}
