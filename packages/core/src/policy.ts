import type { Decision, Finding, PolicyConfig, PolicyRule, RiskLevel } from "./types.js";
import type { EvaluateRequest } from "./types.js";

export const DEFAULT_POLICY: PolicyConfig = {
  default_decision: "allow",
  rules: [
    {
      id: "pol.block_critical_secrets",
      name: "Block critical secret leakage",
      enabled: true,
      effect: "block",
      match: {
        finding_codes: [
          "secret.private_key",
          "secret.aws_access_key",
          "secret.aws_secret",
          "secret.stripe",
          "secret.openai",
          "secret.anthropic",
          "secret.github_pat",
          "secret.github_fine",
          "secret.slack",
          "secret.password_assignment",
          "secret.jwt",
        ],
      },
    },
    {
      id: "pol.block_injection",
      name: "Block critical prompt injection",
      enabled: true,
      effect: "block",
      match: {
        finding_codes: [
          "injection.ignore_instructions",
          "injection.exfiltrate",
          "injection.disable_safety",
        ],
      },
    },
    {
      id: "pol.block_ssrf",
      name: "Block SSRF-like destinations",
      enabled: true,
      effect: "block",
      match: { finding_codes: ["tool.ssrf_local"] },
    },
    {
      id: "pol.approve_high_amount",
      name: "Human approval for high-value amounts",
      enabled: true,
      effect: "approval_required",
      match: { finding_codes: ["tool.high_amount"] },
      require_approval: true,
    },
    {
      id: "pol.approve_shell",
      name: "Human approval for shell/exec",
      enabled: true,
      effect: "approval_required",
      match: { tools: ["shell", "bash", "exec", "run_command"] },
      require_approval: true,
    },
    {
      id: "pol.approve_trajectory_critical",
      name: "Human approval for critical trajectory patterns",
      enabled: true,
      effect: "approval_required",
      match: {
        finding_codes: [
          "traj.recon_then_exfil",
          "traj.cred_harvest",
          "traj.download_exec",
        ],
      },
      require_approval: true,
    },
    {
      id: "pol.block_destructive",
      name: "Block destructive payloads",
      enabled: true,
      effect: "block",
      match: { finding_codes: ["tool.destructive_payload", "tool.exfil_destination"] },
    },
    {
      id: "pol.block_scope_denied",
      name: "Block out-of-scope tool use",
      enabled: true,
      effect: "block",
      match: { finding_codes: ["identity.scope_denied"] },
    },
    {
      id: "pol.block_mcp_poison",
      name: "Block MCP descriptor poisoning",
      enabled: true,
      effect: "block",
      match: { finding_codes: ["mcp.exfil_instruction", "mcp.forced_invocation"] },
    },
    {
      id: "pol.block_egress",
      name: "Block non-allowlisted egress",
      enabled: true,
      effect: "block",
      match: { finding_codes: ["egress.not_allowlisted", "egress.no_allowlist"] },
    },
    {
      id: "pol.block_blast_radius",
      name: "Block blast-radius limit exceeded",
      enabled: true,
      effect: "block",
      match: { finding_codes: ["blast.limit_exceeded"] },
    },
    {
      id: "pol.approve_untrusted_high_impact",
      name: "Approve high-impact tools with untrusted context",
      enabled: true,
      effect: "approval_required",
      match: { finding_codes: ["untrusted.high_impact_tool"] },
      require_approval: true,
    },
    {
      id: "pol.block_mcp_trust",
      name: "Block MCP pin violations",
      enabled: true,
      effect: "block",
      match: { finding_codes: ["mcp.pin_violation"] },
    },
    {
      id: "pol.approve_mcp_unknown",
      name: "Approve unknown MCP servers",
      enabled: true,
      effect: "approval_required",
      match: { finding_codes: ["mcp.untrusted_server", "mcp.descriptor_drift"] },
      require_approval: true,
    },
    {
      id: "pol.block_output_secrets",
      name: "Block secret leakage in tool output",
      enabled: true,
      effect: "block",
      match: {
        finding_codes: [
          "output.private_key",
          "output.aws_access_key",
          "output.openai",
          "output.anthropic",
          "output.stripe",
          "output.github_pat",
          "output.github_fine",
          "output.slack",
          "output.password_assignment",
          "output.jwt",
        ],
      },
    },
  ],
};

/** Merge shipped default rules into a persisted policy (union finding_codes; add missing rules). */
export function mergePolicyWithDefaults(stored: PolicyConfig, defaults: PolicyConfig = DEFAULT_POLICY): PolicyConfig {
  const rules: PolicyRule[] = stored.rules.map((r) => structuredClone(r));
  const byId = new Map(rules.map((r) => [r.id, r]));
  for (const def of defaults.rules) {
    const existing = byId.get(def.id);
    if (!existing) {
      const cloned = structuredClone(def);
      rules.push(cloned);
      byId.set(def.id, cloned);
      continue;
    }
    if (def.match?.finding_codes?.length) {
      const codes = new Set([...(existing.match?.finding_codes ?? []), ...def.match.finding_codes]);
      existing.match = { ...(existing.match ?? {}), finding_codes: [...codes] };
    }
  }
  return {
    default_decision: stored.default_decision ?? defaults.default_decision,
    rules,
  };
}


const RANK: Record<Decision, number> = {
  allow: 0,
  approval_required: 1,
  block: 2,
};

export function riskLevelFromScore(score: number): RiskLevel {
  if (score >= 85) return "critical";
  if (score >= 65) return "high";
  if (score >= 35) return "medium";
  return "low";
}

export function scoreFindings(findings: Finding[]): number {
  let score = 0;
  for (const f of findings) {
    score += f.severity === "critical" ? 40 : f.severity === "high" ? 25 : f.severity === "medium" ? 12 : 5;
  }
  return Math.min(100, score);
}

function ruleMatches(
  rule: PolicyRule,
  req: Pick<EvaluateRequest, "agent" | "action"> & { destination?: string },
  findings: Finding[],
  riskScore: number,
): boolean {
  if (!rule.enabled) return false;
  if (rule.min_risk_score != null && riskScore < rule.min_risk_score) return false;
  const m = rule.match;
  if (!m) return rule.min_risk_score != null;

  if (m.agent_ids?.length && !m.agent_ids.includes(req.agent.agent_id)) return false;
  if (m.action_types?.length && !m.action_types.includes(req.action.type)) return false;
  if (m.tools?.length && !m.tools.map((t) => t.toLowerCase()).includes(req.action.tool.toLowerCase())) {
    return false;
  }
  if (m.scopes_any?.length) {
    const scopes = req.agent.scopes ?? [];
    if (!m.scopes_any.some((s) => scopes.includes(s))) return false;
  }
  if (m.destinations_regex?.length) {
    const dest = req.destination || req.action.destination || "";
    if (!m.destinations_regex.some((r) => new RegExp(r, "i").test(dest))) return false;
  }
  if (m.finding_codes?.length) {
    const codes = new Set(findings.map((f) => f.code));
    if (!m.finding_codes.some((c) => codes.has(c))) return false;
  }
  return true;
}

export function applyPolicies(
  config: PolicyConfig,
  req: Pick<EvaluateRequest, "agent" | "action"> & { destination?: string },
  findings: Finding[],
): { decision: Decision; matched: PolicyRule[]; risk_score: number; risk_level: RiskLevel } {
  const risk_score = scoreFindings(findings);
  const risk_level = riskLevelFromScore(risk_score);
  let decision = config.default_decision;
  const matched: PolicyRule[] = [];

  for (const rule of config.rules) {
    if (!ruleMatches(rule, req, findings, risk_score)) continue;
    matched.push(rule);
    if (RANK[rule.effect] > RANK[decision]) decision = rule.effect;
  }

  // Safety net: critical findings without an explicit allow path escalate
  if (findings.some((f) => f.severity === "critical") && decision === "allow") {
    decision = "approval_required";
  }

  return { decision, matched, risk_score, risk_level };
}
