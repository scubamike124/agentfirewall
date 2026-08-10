export type Decision = "allow" | "block" | "approval_required";

export interface AgentFirewallClientOptions {
  apiKey: string;
  baseUrl?: string;
  agentId: string;
  /** Short-lived agent credential (required when server is fail-closed). */
  agentToken?: string;
  sessionId?: string;
  /** If true, throw when decision is block */
  throwOnBlock?: boolean;
  /** If true, throw when approval is required (caller must handle approvals) */
  throwOnApprovalRequired?: boolean;
}

export class AgentFirewallError extends Error {
  constructor(
    message: string,
    public decision: Decision,
    public evaluation: unknown,
  ) {
    super(message);
    this.name = "AgentFirewallError";
  }
}

type EvalResult = {
  decision: Decision;
  explanation: string;
  evaluation_id: string;
  approval_id?: string;
  action_hash?: string;
  resume_token?: string;
  approval_expires_at?: string;
  human_approved?: boolean;
};

export class AgentFirewallClient {
  private apiKey: string;
  private baseUrl: string;
  private agentId: string;
  private agentToken?: string;
  private sessionId?: string;
  private throwOnBlock: boolean;
  private throwOnApprovalRequired: boolean;
  private history: Array<{ type: string; tool: string; parameters?: Record<string, unknown>; destination?: string }> =
    [];

  constructor(opts: AgentFirewallClientOptions) {
    this.apiKey = opts.apiKey;
    this.baseUrl = (opts.baseUrl ?? "http://localhost:8787").replace(/\/$/, "");
    this.agentId = opts.agentId;
    this.agentToken = opts.agentToken;
    this.sessionId = opts.sessionId;
    this.throwOnBlock = opts.throwOnBlock ?? true;
    this.throwOnApprovalRequired = opts.throwOnApprovalRequired ?? true;
  }

  setAgentToken(token: string): void {
    this.agentToken = token;
  }

  /** Issue a short-lived agent credential from the API. */
  async issueCredential(opts?: {
    scopes?: string[];
    egress_allowlist?: string[];
    ttl?: number;
  }): Promise<{ token: string; expires_at: string }> {
    const q = opts?.ttl != null ? `?ttl=${opts.ttl}` : "";
    const res = await fetch(`${this.baseUrl}/v1/agents${q}`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${this.apiKey}`,
      },
      body: JSON.stringify({
        agent_id: this.agentId,
        scopes: opts?.scopes,
        egress_allowlist: opts?.egress_allowlist,
      }),
    });
    if (!res.ok) throw new Error(`issueCredential failed: ${res.status} ${await res.text()}`);
    const data = (await res.json()) as { token: string; expires_at: string };
    this.agentToken = data.token;
    return data;
  }

  async evaluate(
    action: {
      type?: string;
      tool: string;
      parameters?: Record<string, unknown>;
      destination?: string;
      amount?: number;
      currency?: string;
    },
    context?: {
      untrusted_content?: string[];
      mcp_descriptions?: Array<string | { server?: string; name?: string; description?: string }>;
      messages?: string[];
    },
  ): Promise<EvalResult> {
    const body = {
      agent: { agent_id: this.agentId },
      agent_token: this.agentToken,
      action: {
        type: action.type ?? "tool_call",
        tool: action.tool,
        parameters: action.parameters,
        destination: action.destination,
        amount: action.amount,
        currency: action.currency,
      },
      context: {
        session_id: this.sessionId,
        prior_actions: this.history.slice(-20),
        ...context,
      },
      destination: action.destination,
    };

    const res = await fetch(`${this.baseUrl}/v1/evaluate`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${this.apiKey}`,
      },
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      throw new Error(`AgentFirewall evaluate failed: ${res.status} ${await res.text()}`);
    }
    const evaluation = (await res.json()) as EvalResult;

    if (evaluation.decision === "block" && this.throwOnBlock) {
      throw new AgentFirewallError(evaluation.explanation, "block", evaluation);
    }
    if (evaluation.decision === "approval_required" && this.throwOnApprovalRequired) {
      throw new AgentFirewallError(evaluation.explanation, "approval_required", evaluation);
    }

    if (evaluation.decision === "allow") {
      this.history.push({
        type: body.action.type,
        tool: body.action.tool,
        parameters: body.action.parameters,
        destination: body.action.destination,
      });
    }

    return evaluation;
  }

  async inspectOutput(result: unknown, tool?: string) {
    const res = await fetch(`${this.baseUrl}/v1/inspect/output`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${this.apiKey}`,
      },
      body: JSON.stringify({
        agent_id: this.agentId,
        agent_token: this.agentToken,
        tool,
        result,
      }),
    });
    if (!res.ok) throw new Error(`inspectOutput failed: ${res.status} ${await res.text()}`);
    return res.json() as Promise<{
      decision: Decision;
      result_redacted: unknown;
      findings: unknown[];
      explanation: string;
    }>;
  }

  /** Force HTTP through the non-bypassable gate (evaluate + optional fetch + output DLP). */
  async gatedFetch(url: string, init?: RequestInit & { execute?: boolean; session_id?: string }) {
    if (!this.agentToken) throw new Error("agentToken required for gatedFetch — call issueCredential()");
    const res = await fetch(`${this.baseUrl}/v1/gate/http`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${this.apiKey}`,
      },
      body: JSON.stringify({
        agent_id: this.agentId,
        agent_token: this.agentToken,
        url,
        method: init?.method ?? "GET",
        headers: init?.headers as Record<string, string> | undefined,
        body: typeof init?.body === "string" ? init.body : undefined,
        execute: init?.execute ?? true,
        session_id: init?.session_id ?? this.sessionId,
      }),
    });
    const data = await res.json();
    if (!res.ok && res.status !== 202) {
      throw new AgentFirewallError(
        (data as { evaluation?: { explanation?: string } }).evaluation?.explanation ??
          `gatedFetch blocked: ${res.status}`,
        "block",
        data,
      );
    }
    return data;
  }

  async listApprovals(): Promise<
    Array<{ id: string; status: string; agent_id: string; action_summary: string }>
  > {
    const res = await fetch(`${this.baseUrl}/v1/approvals`, {
      headers: { authorization: `Bearer ${this.apiKey}` },
    });
    if (!res.ok) throw new Error(`listApprovals failed: ${res.status}`);
    const data = (await res.json()) as {
      approvals: Array<{ id: string; status: string; agent_id: string; action_summary: string }>;
    };
    return data.approvals;
  }

  async resolveApproval(
    approvalId: string,
    status: "approved" | "denied",
    note?: string,
    resolvedBy?: string,
  ) {
    const res = await fetch(`${this.baseUrl}/v1/approvals/${approvalId}/resolve`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${this.apiKey}`,
      },
      body: JSON.stringify({ status, note, resolved_by: resolvedBy }),
    });
    if (!res.ok) throw new Error(`resolveApproval failed: ${res.status}`);
    return res.json();
  }

  async resumeApproval(
    approvalId: string,
    resumeToken: string,
    action: {
      type?: string;
      tool: string;
      parameters?: Record<string, unknown>;
      destination?: string;
      amount?: number;
      currency?: string;
    },
  ) {
    const res = await fetch(`${this.baseUrl}/v1/approvals/${approvalId}/resume`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${this.apiKey}`,
      },
      body: JSON.stringify({
        resume_token: resumeToken,
        action: {
          type: action.type ?? "tool_call",
          tool: action.tool,
          parameters: action.parameters,
          destination: action.destination,
          amount: action.amount,
          currency: action.currency,
        },
        destination: action.destination,
      }),
    });
    if (!res.ok) throw new Error(`resumeApproval failed: ${res.status} ${await res.text()}`);
    return res.json() as Promise<{ decision: Decision; human_approved: boolean }>;
  }

  async waitForApproval(
    approvalId: string,
    opts?: { timeoutMs?: number; intervalMs?: number },
  ): Promise<"approved" | "denied" | "expired"> {
    const timeoutMs = opts?.timeoutMs ?? 120_000;
    const intervalMs = opts?.intervalMs ?? 2_000;
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
      const approvals = await this.listApprovals();
      const hit = approvals.find((a) => a.id === approvalId);
      if (hit && (hit.status === "approved" || hit.status === "denied" || hit.status === "expired")) {
        return hit.status as "approved" | "denied" | "expired";
      }
      await new Promise((r) => setTimeout(r, intervalMs));
    }
    throw new Error(`Timed out waiting for approval ${approvalId}`);
  }

  /**
   * Evaluate; if approval_required, wait for human, then resume with bound action hash.
   * Timeout / deny ⇒ block (fail closed).
   */
  async evaluateWithApproval(
    action: {
      type?: string;
      tool: string;
      parameters?: Record<string, unknown>;
      destination?: string;
      amount?: number;
      currency?: string;
    },
    context?: {
      untrusted_content?: string[];
      mcp_descriptions?: Array<string | { server?: string; name?: string; description?: string }>;
      messages?: string[];
    },
    waitOpts?: { timeoutMs?: number; intervalMs?: number },
  ) {
    const prev = this.throwOnApprovalRequired;
    this.throwOnApprovalRequired = false;
    try {
      const evaluation = await this.evaluate(action, context);
      if (evaluation.decision !== "approval_required" || !evaluation.approval_id) {
        return evaluation;
      }
      if (!evaluation.resume_token) {
        throw new AgentFirewallError("Missing resume_token for bound approval", "block", evaluation);
      }
      const status = await this.waitForApproval(evaluation.approval_id, waitOpts);
      if (status !== "approved") {
        throw new AgentFirewallError(
          status === "expired" ? "Approval expired — denied by default" : "Human denied the action",
          "block",
          { evaluation, status },
        );
      }
      const resumed = await this.resumeApproval(evaluation.approval_id, evaluation.resume_token, {
        type: action.type ?? "tool_call",
        tool: action.tool,
        parameters: action.parameters,
        destination: action.destination,
        amount: action.amount,
        currency: action.currency,
      });
      this.history.push({
        type: action.type ?? "tool_call",
        tool: action.tool,
        parameters: action.parameters,
        destination: action.destination,
      });
      return { ...evaluation, decision: resumed.decision, human_approved: true };
    } finally {
      this.throwOnApprovalRequired = prev;
    }
  }

  /** Wrap any async tool with pre-eval + post-output DLP. */
  wrapTool<TArgs extends Record<string, unknown>, TResult>(
    tool: string,
    fn: (args: TArgs) => Promise<TResult> | TResult,
    opts?: { type?: string; destinationFromArgs?: (args: TArgs) => string | undefined },
  ) {
    return async (args: TArgs): Promise<TResult> => {
      await this.evaluate({
        type: opts?.type ?? "tool_call",
        tool,
        parameters: args,
        destination: opts?.destinationFromArgs?.(args),
      });
      const result = await fn(args);
      const out = await this.inspectOutput(result, tool);
      if (out.decision === "block" && this.throwOnBlock) {
        throw new AgentFirewallError(out.explanation, "block", out);
      }
      return (out.result_redacted as TResult) ?? result;
    };
  }

  async evaluateTrajectory(proposed?: {
    type?: string;
    tool: string;
    parameters?: Record<string, unknown>;
    destination?: string;
  }) {
    const res = await fetch(`${this.baseUrl}/v1/trajectory/evaluate`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${this.apiKey}`,
      },
      body: JSON.stringify({
        agent: { agent_id: this.agentId },
        agent_token: this.agentToken,
        history: this.history.map((a) => ({ action: a })),
        proposed: proposed
          ? {
              type: proposed.type ?? "tool_call",
              tool: proposed.tool,
              parameters: proposed.parameters,
              destination: proposed.destination,
            }
          : undefined,
        session_id: this.sessionId,
      }),
    });
    if (!res.ok) throw new Error(`trajectory evaluate failed: ${res.status}`);
    return res.json();
  }

  async evaluateMcp(
    tool: string,
    parameters: Record<string, unknown> | undefined,
    mcpDescriptions: Array<string | { server?: string; name?: string; description?: string }>,
  ) {
    return this.evaluate(
      { type: "mcp_call", tool, parameters },
      { mcp_descriptions: mcpDescriptions },
    );
  }
}
