/** Shared types for the Agent Security Firewall core. */

export type Decision = "allow" | "block" | "approval_required";

export type RiskLevel = "low" | "medium" | "high" | "critical";

export interface AgentIdentity {
  agent_id: string;
  display_name?: string;
  scopes?: string[];
  /** Short-lived credential id (not the secret). */
  credential_id?: string;
  org_id?: string;
  /** Allowed egress destinations (hosts, prefixes, `*.domain`, `/regex/`). */
  egress_allowlist?: string[];
}

export interface ProposedAction {
  /** High-level action class, e.g. tool_call, http_request, db_query, mcp_call */
  type: string;
  tool: string;
  parameters?: Record<string, unknown>;
  destination?: string;
  /** Free-form amount for payment/transfer style tools */
  amount?: number;
  currency?: string;
}

export interface EvaluationContext {
  session_id?: string;
  /** Prior actions in this session (for inline trajectory hints). */
  prior_actions?: ProposedAction[];
  /** Untrusted text the agent is about to act on (web, docs, tool output). */
  untrusted_content?: string[];
  /** MCP tool/server descriptions (string or structured). */
  mcp_descriptions?: Array<string | { server?: string; name?: string; description?: string }>;
  /** Recent chat / instruction fragments. */
  messages?: string[];
  metadata?: Record<string, unknown>;
}

export interface EvaluateRequest {
  agent: AgentIdentity;
  action: ProposedAction;
  context?: EvaluationContext;
  destination?: string;
  /** Idempotency / correlation */
  request_id?: string;
}

export interface Finding {
  detector: string;
  severity: RiskLevel;
  code: string;
  message: string;
  evidence?: string;
}

export interface EvaluateResponse {
  evaluation_id: string;
  decision: Decision;
  risk_score: number;
  risk_level: RiskLevel;
  explanation: string;
  findings: Finding[];
  policy_ids: string[];
  approval_id?: string;
  /** SHA-256 of the bound action — required to resume after approval. */
  action_hash?: string;
  /** One-time resume secret (only when approval_required). */
  resume_token?: string;
  approval_expires_at?: string;
  agent_id: string;
  timestamp: string;
}

export interface TrajectoryStep {
  action: ProposedAction;
  evaluation_id?: string;
  decision?: Decision;
  timestamp?: string;
}

export interface TrajectoryEvaluateRequest {
  agent: AgentIdentity;
  history: TrajectoryStep[];
  /** Optional pending action to append conceptually */
  proposed?: ProposedAction;
  session_id?: string;
  request_id?: string;
}

export interface TrajectoryEvaluateResponse {
  evaluation_id: string;
  decision: Decision;
  risk_score: number;
  risk_level: RiskLevel;
  explanation: string;
  findings: Finding[];
  pattern_ids: string[];
  approval_id?: string;
  agent_id: string;
  timestamp: string;
}

export interface AuditRecord {
  id: string;
  kind: "evaluate" | "trajectory" | "approval" | "webhook";
  agent_id: string;
  tool?: string;
  action_type?: string;
  destination?: string | null;
  decision: Decision;
  risk_score: number;
  explanation: string;
  findings: Finding[];
  parameters_redacted?: Record<string, unknown>;
  session_id?: string;
  approval_id?: string;
  timestamp: string;
  result?: string;
}

export type PolicyEffect = Decision;

export interface PolicyRule {
  id: string;
  name: string;
  enabled: boolean;
  /** If match, apply this effect (highest severity wins among matches). */
  effect: PolicyEffect;
  /** Minimum risk score to trigger (0-100) when using detector aggregate */
  min_risk_score?: number;
  match?: {
    action_types?: string[];
    tools?: string[];
    destinations_regex?: string[];
    agent_ids?: string[];
    scopes_any?: string[];
    finding_codes?: string[];
  };
  require_approval?: boolean;
}

export interface PolicyConfig {
  default_decision: Decision;
  rules: PolicyRule[];
}
