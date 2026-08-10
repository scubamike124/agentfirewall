import { Hono } from "hono";
import { cors } from "hono/cors";
import { z } from "zod";
import { createHash } from "crypto";
import { AsyncLocalStorage } from "async_hooks";
import {
  AgentCredentialStore,
  FirewallEngine,
  TIER_LIMITS,
  resolveTier,
  hashAction,
  inspectToolOutput,
  type EvaluateRequest,
  type TrajectoryEvaluateRequest,
  type EgressMode,
  type Tier,
} from "@agentfirewall/core";
import {
  appendAudit,
  appendSessionStep,
  bumpEvaluationUsage,
  clearSession,
  dataDirPath,
  dispatchWebhooks,
  expireStaleApprovals,
  exportAuditCsv,
  exportAuditSiem,
  getApproval,
  getEvaluationUsage,
  getSession,
  listAllSessions,
  listApprovals,
  listAudit,
  listSessionActions,
  loadMcpTrust,
  loadPolicy,
  loadWebhooks,
  pruneAudit,
  saveApproval,
  saveMcpTrust,
  savePolicy,
  saveWebhooks,
} from "./store.js";
import { openApiDocument } from "./openapi.js";
import {
  getBillingPlans,
  applySubscriptionEvent,
  createCheckoutSession,
  loadEntitlement,
  planById,
  retrieveCheckoutSession,
  verifyStripeWebhook,
} from "./billing.js";
import { contactConfigured, sendContactEmail, sendCustomerEmail } from "./contact.js";
import {
  bumpCustomerUsage,
  consumeKeyReveal,
  findCustomerByEmail,
  findCustomerByKey,
  findCustomerByStripeCustomer,
  getCustomerUsage,
  issueCustomer,
  saveKeyReveal,
  updateCustomerBilling,
  type Customer,
  type PlanId,
} from "./customers.js";
import path from "path";

function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

type Auth =
  | { kind: "master"; tier: Tier }
  | { kind: "customer"; customer: Customer; tier: Tier };

const authAls = new AsyncLocalStorage<{ auth: Auth | null }>();

function effectiveTier(): Tier {
  const ent = loadEntitlement();
  if (ent.status === "active" && ent.tier) return resolveTier(ent.tier);
  return resolveTier();
}

function publicSiteBase(): string {
  return (
    process.env.AGENTFIREWALL_SITE_URL?.replace(/\/$/, "") ||
    "https://agentfirewall.launchreadyal.com"
  );
}

function apiPublicBase(fallbackOrigin: string): string {
  return (
    process.env.AGENTFIREWALL_PUBLIC_URL?.replace(/\/$/, "") ||
    fallbackOrigin.replace(/\/$/, "")
  );
}

const signupHits = new Map<string, number[]>();
function signupRateOk(ip: string, max = 5): boolean {
  const now = Date.now();
  const windowMs = 15 * 60 * 1000;
  const list = (signupHits.get(ip) ?? []).filter((t) => now - t < windowMs);
  if (list.length >= max) {
    signupHits.set(ip, list);
    return false;
  }
  list.push(now);
  signupHits.set(ip, list);
  return true;
}

export function createApp(opts?: { apiKey?: string }) {
  const API_KEY = opts?.apiKey ?? process.env.AGENTFIREWALL_API_KEY ?? "af_dev_key_change_me";
  const requireAgentToken = process.env.AGENTFIREWALL_REQUIRE_AGENT_TOKEN !== "0";
  const egressMode = (process.env.AGENTFIREWALL_EGRESS_MODE as EgressMode) || "observe";

  function resolveAuth(rawKey: string | undefined): Auth | null {
    if (!rawKey) return null;
    if (rawKey === API_KEY) return { kind: "master", tier: effectiveTier() };
    const customer = findCustomerByKey(rawKey);
    if (!customer) return null;
    if (customer.status === "canceled") return null;
    return { kind: "customer", customer, tier: customer.tier };
  }

  const tier = () => authAls.getStore()?.auth?.tier ?? effectiveTier();
  const limits = () => TIER_LIMITS[tier()];
  const currentCustomer = () => {
    const a = authAls.getStore()?.auth;
    return a?.kind === "customer" ? a.customer : null;
  };

  const engine = new FirewallEngine({
    policy: loadPolicy(),
    egressMode,
    mcpTrust: loadMcpTrust(),
    onMcpTrustChange: (reg) => saveMcpTrust(reg),
    onAudit: async (record) => {
      appendAudit(record);
      if (record.decision !== "allow") {
        await dispatchWebhooks("security.decision", record as unknown as Record<string, unknown>);
      }
    },
  });

  const credentials = new AgentCredentialStore(path.join(dataDirPath(), "agents.json"));
  const app = new Hono();
  app.use("*", cors({ origin: "*", allowHeaders: ["Content-Type", "Authorization", "X-Api-Key"] }));

  app.use("*", async (c, next) => {
    const raw =
      c.req.header("authorization")?.replace(/^Bearer\s+/i, "") ?? c.req.header("x-api-key");
    const auth = resolveAuth(raw);
    await authAls.run({ auth }, async () => {
      await next();
    });
  });

  app.get("/health", (c) =>
    c.json({
      ok: true,
      product: "AgentFirewall",
      tagline: "Real-time AI Agent Security Firewall",
      model_agnostic: true,
      tier: "developer",
      require_agent_token: requireAgentToken,
      egress_mode: egressMode,
      signup: true,
      checkout: true,
    }),
  );

  app.get("/v1/openapi.json", (c) => c.json(openApiDocument));
  app.get("/openapi.json", (c) => c.json(openApiDocument));

  function requireApiKey(c: { req: { header: (n: string) => string | undefined } }): boolean {
    const key =
      c.req.header("authorization")?.replace(/^Bearer\s+/i, "") ?? c.req.header("x-api-key");
    return resolveAuth(key) !== null;
  }

  function clientIp(c: {
    req: { header: (n: string) => string | undefined };
  }): string {
    return (
      c.req.header("x-forwarded-for")?.split(",")[0]?.trim() ||
      c.req.header("cf-connecting-ip") ||
      "local"
    );
  }

  async function deliverApiKeyEmail(opts: {
    email: string;
    apiKey: string;
    plan: string;
  }): Promise<void> {
    await sendCustomerEmail({
      to: opts.email,
      subject: `Your AgentFirewall ${opts.plan} API key`,
      text: [
        `Welcome to AgentFirewall (${opts.plan}).`,
        "",
        "Your API key (store it securely — it won't be shown again in email clients that hide it):",
        opts.apiKey,
        "",
        "Quick start:",
        "1) POST /v1/agents with Authorization: Bearer <api_key>",
        "2) POST /v1/evaluate with agent_token from step 1",
        "",
        `API: ${apiPublicBase("https://api.agentfirewall.launchreadyal.com")}`,
        `Docs: ${apiPublicBase("https://api.agentfirewall.launchreadyal.com")}/v1/openapi.json`,
        `Site: ${publicSiteBase()}`,
      ].join("\n"),
    });
  }

  app.get("/v1/meta", (c) => {
    if (!requireApiKey(c)) return c.json({ error: "Unauthorized" }, 401);
    expireStaleApprovals();
    const t = tier();
    const lim = limits();
    const cust = currentCustomer();
    const billing = cust
      ? {
          plan_id: cust.plan_id,
          tier: cust.tier,
          status: cust.status,
          email: cust.email,
        }
      : loadEntitlement();
    const usage = cust ? getCustomerUsage(cust.id) : getEvaluationUsage();
    return c.json({
      tier: t,
      limits: lim,
      billing,
      usage,
      require_agent_token: requireAgentToken,
      egress_mode: egressMode,
      systems: [
        "agent_identity",
        "runtime_action_control",
        "prompt_injection_mcp_poisoning",
        "trajectory_detection",
        "secrets_dlp",
        "audit_forensics",
        "egress_allowlist",
        "bound_approvals",
        "output_dlp",
        "mcp_trust",
        "untrusted_content_gate",
        "blast_radius",
        "enforcement_gate",
        "billing_stripe",
        "multi_tenant_keys",
      ],
    });
  });

  const agentSchema = z.object({
    agent_id: z.string().min(1),
    display_name: z.string().optional(),
    scopes: z.array(z.string()).optional(),
    credential_id: z.string().optional(),
    org_id: z.string().optional(),
    egress_allowlist: z.array(z.string()).optional(),
  });

  const actionSchema = z.object({
    type: z.string().min(1),
    tool: z.string().min(1),
    parameters: z.record(z.unknown()).optional(),
    destination: z.string().optional(),
    amount: z.number().optional(),
    currency: z.string().optional(),
  });

  app.post("/v1/agents", async (c) => {
    if (!requireApiKey(c)) return c.json({ error: "Unauthorized" }, 401);
    const body = agentSchema.parse(await c.req.json());
    const cust = currentCustomer();
    const orgId = cust?.id ?? body.org_id;
    const agentBody = { ...body, org_id: orgId };
    const owned = cust
      ? credentials.listAgents().filter((a) => a.org_id === cust.id)
      : credentials.listAgents();
    if (owned.length >= limits().max_agents && !credentials.getAgent(body.agent_id)) {
      return c.json({ error: `Agent limit reached for tier ${tier()} (${limits().max_agents})` }, 403);
    }
    const issued = credentials.issue(agentBody, Number(c.req.query("ttl") ?? 3600));
    return c.json({
      agent_id: issued.agent_id,
      credential_id: issued.credential_id,
      token: issued.token,
      scopes: issued.scopes,
      expires_at: issued.expires_at,
      egress_allowlist: credentials.getAgent(issued.agent_id)?.egress_allowlist ?? body.egress_allowlist,
      note: "Short-lived agent credential — required on evaluate when require_agent_token is enabled.",
    });
  });

  app.get("/v1/agents", (c) => {
    if (!requireApiKey(c)) return c.json({ error: "Unauthorized" }, 401);
    const cust = currentCustomer();
    const agents = cust
      ? credentials.listAgents().filter((a) => a.org_id === cust.id)
      : credentials.listAgents();
    return c.json({ agents });
  });

  app.put("/v1/agents/:id/egress", async (c) => {
    if (!requireApiKey(c)) return c.json({ error: "Unauthorized" }, 401);
    const body = z.object({ allowlist: z.array(z.string()) }).parse(await c.req.json());
    const updated = credentials.setEgressAllowlist(c.req.param("id"), body.allowlist);
    if (!updated) return c.json({ error: "Agent not found — create via POST /v1/agents first" }, 404);
    return c.json({ agent: updated });
  });

  app.post("/v1/evaluate", async (c) => {
    if (!requireApiKey(c)) return c.json({ error: "Unauthorized" }, 401);
    expireStaleApprovals();
    const cust = currentCustomer();
    const used = cust ? bumpCustomerUsage(cust.id) : bumpEvaluationUsage();
    if (used > limits().evaluations_per_day) {
      return c.json(
        {
          error: "Daily evaluation quota exceeded",
          tier: tier(),
          limit: limits().evaluations_per_day,
          used,
        },
        429,
      );
    }
    const raw = await c.req.json();
    const body = z
      .object({
        agent: agentSchema,
        action: actionSchema,
        context: z
          .object({
            session_id: z.string().optional(),
            prior_actions: z.array(actionSchema).optional(),
            untrusted_content: z.array(z.string()).optional(),
            mcp_descriptions: z.array(z.union([z.string(), z.record(z.unknown())])).optional(),
            messages: z.array(z.string()).optional(),
            metadata: z.record(z.unknown()).optional(),
          })
          .optional(),
        destination: z.string().optional(),
        request_id: z.string().optional(),
        agent_token: z.string().optional(),
      })
      .parse(raw);

    if (requireAgentToken && !body.agent_token) {
      return c.json(
        {
          error: "agent_token required (fail-closed identity)",
          hint: "POST /v1/agents to issue a short-lived credential, or set AGENTFIREWALL_REQUIRE_AGENT_TOKEN=0",
        },
        401,
      );
    }

    let agent = body.agent;
    if (body.agent_token) {
      const cred = credentials.verify(body.agent_token);
      if (!cred) return c.json({ error: "Invalid or expired agent credential" }, 401);
      if (cred.agent_id !== body.agent.agent_id) {
        return c.json({ error: "agent_token does not match agent_id" }, 403);
      }
      const registered = credentials.getAgent(cred.agent_id);
      agent = {
        ...body.agent,
        scopes: cred.scopes,
        credential_id: cred.credential_id,
        org_id: cred.org_id ?? body.agent.org_id,
        egress_allowlist: body.agent.egress_allowlist ?? registered?.egress_allowlist,
      };
    } else {
      credentials.upsertAgent(body.agent);
      const registered = credentials.getAgent(body.agent.agent_id);
      agent = {
        ...body.agent,
        egress_allowlist: body.agent.egress_allowlist ?? registered?.egress_allowlist,
      };
    }

    // Client cannot self-escalate scopes when token is present (already using cred.scopes)
    const evalReq = { ...body, agent } as EvaluateRequest;
    const sessionId = evalReq.context?.session_id;
    const sessionPrior = sessionId
      ? listSessionActions(evalReq.agent.agent_id, sessionId)
      : [];
    const clientPrior = evalReq.context?.prior_actions ?? [];
    const prior_actions = [...sessionPrior, ...clientPrior].slice(-40);

    const result = await engine.evaluate({
      ...evalReq,
      context: {
        ...evalReq.context,
        prior_actions,
        mcp_descriptions: evalReq.context?.mcp_descriptions as string[] | undefined,
      },
    });

    if (sessionId) {
      appendSessionStep(evalReq.agent.agent_id, sessionId, {
        action: evalReq.action,
        evaluation_id: result.evaluation_id,
        decision: result.decision,
        timestamp: result.timestamp,
      });
    }

    if (result.decision === "approval_required" && result.approval_id && result.resume_token) {
      saveApproval({
        id: result.approval_id,
        evaluation_id: result.evaluation_id,
        agent_id: result.agent_id,
        status: "pending",
        created_at: result.timestamp,
        expires_at: result.approval_expires_at,
        action_summary: `${evalReq.action.type}:${evalReq.action.tool}`,
        action_hash: result.action_hash,
        action: evalReq.action,
        destination: evalReq.destination ?? evalReq.action.destination,
        resume_token_hash: hashToken(result.resume_token),
      });
      await dispatchWebhooks("approval.required", {
        approval_id: result.approval_id,
        action_hash: result.action_hash,
        evaluation: { ...result, resume_token: undefined },
      });
    }

    return c.json({
      ...result,
      session: sessionId
        ? {
            session_id: sessionId,
            steps_recorded: getSession(evalReq.agent.agent_id, sessionId)?.steps.length ?? 0,
          }
        : undefined,
      blast: engine.getBlastTracker().snapshot(evalReq.agent.agent_id),
    });
  });

  app.post("/v1/trajectory/evaluate", async (c) => {
    if (!requireApiKey(c)) return c.json({ error: "Unauthorized" }, 401);
    const raw = await c.req.json();
    const body = z
      .object({
        agent: agentSchema,
        history: z
          .array(
            z.object({
              action: actionSchema,
              evaluation_id: z.string().optional(),
              decision: z.enum(["allow", "block", "approval_required"]).optional(),
              timestamp: z.string().optional(),
            }),
          )
          .optional(),
        proposed: actionSchema.optional(),
        session_id: z.string().optional(),
        request_id: z.string().optional(),
        agent_token: z.string().optional(),
      })
      .parse(raw);

    if (requireAgentToken && !body.agent_token) {
      return c.json({ error: "agent_token required (fail-closed identity)" }, 401);
    }
    if (body.agent_token) {
      const cred = credentials.verify(body.agent_token);
      if (!cred || cred.agent_id !== body.agent.agent_id) {
        return c.json({ error: "Invalid agent credential" }, 401);
      }
    }

    const sessionSteps =
      body.session_id != null
        ? (getSession(body.agent.agent_id, body.session_id)?.steps ?? [])
        : [];
    const history = [...sessionSteps, ...(body.history ?? [])];

    const req: TrajectoryEvaluateRequest = {
      agent: body.agent,
      history,
      proposed: body.proposed,
      session_id: body.session_id,
      request_id: body.request_id,
    };

    const result = await engine.evaluateTrajectory(req);
    if (result.decision === "approval_required" && result.approval_id) {
      saveApproval({
        id: result.approval_id,
        evaluation_id: result.evaluation_id,
        agent_id: result.agent_id,
        status: "pending",
        created_at: result.timestamp,
        action_summary: "trajectory",
      });
      await dispatchWebhooks("approval.required", {
        approval_id: result.approval_id,
        evaluation: result,
      });
    }
    return c.json(result);
  });

  app.post("/v1/inspect/output", async (c) => {
    if (!requireApiKey(c)) return c.json({ error: "Unauthorized" }, 401);
    const body = z
      .object({
        agent_id: z.string().min(1),
        tool: z.string().optional(),
        result: z.unknown(),
        agent_token: z.string().optional(),
      })
      .parse(await c.req.json());

    if (requireAgentToken && !body.agent_token) {
      return c.json({ error: "agent_token required" }, 401);
    }
    if (body.agent_token) {
      const cred = credentials.verify(body.agent_token);
      if (!cred || cred.agent_id !== body.agent_id) {
        return c.json({ error: "Invalid agent credential" }, 401);
      }
    }

    const inspected = inspectToolOutput(body.result, { tool: body.tool });
    appendAudit({
      id: `outdlp_${Date.now()}`,
      kind: "evaluate",
      agent_id: body.agent_id,
      tool: body.tool,
      action_type: "tool_output",
      destination: null,
      decision: inspected.decision,
      risk_score: inspected.risk_score,
      explanation: inspected.explanation,
      findings: inspected.findings,
      timestamp: new Date().toISOString(),
    });
    return c.json(inspected);
  });

  /** Non-bypassable HTTP gate: evaluate then optionally fetch + output DLP. */
  app.post("/v1/gate/http", async (c) => {
    if (!requireApiKey(c)) return c.json({ error: "Unauthorized" }, 401);
    const body = z
      .object({
        agent_id: z.string().min(1),
        agent_token: z.string().min(1),
        url: z.string().url(),
        method: z.string().default("GET"),
        headers: z.record(z.string()).optional(),
        body: z.string().optional(),
        session_id: z.string().optional(),
        execute: z.boolean().default(true),
      })
      .parse(await c.req.json());

    const cred = credentials.verify(body.agent_token);
    if (!cred || cred.agent_id !== body.agent_id) {
      return c.json({ error: "Invalid agent credential" }, 401);
    }
    const registered = credentials.getAgent(body.agent_id);

    const evaluation = await engine.evaluate({
      agent: {
        agent_id: body.agent_id,
        scopes: cred.scopes,
        credential_id: cred.credential_id,
        egress_allowlist: registered?.egress_allowlist,
      },
      action: {
        type: "http_request",
        tool: "http_request",
        parameters: { method: body.method, url: body.url },
        destination: body.url,
      },
      destination: body.url,
      context: { session_id: body.session_id },
    });

    if (evaluation.decision !== "allow") {
      return c.json({ ok: false, evaluation }, evaluation.decision === "block" ? 403 : 202);
    }

    if (!body.execute) {
      return c.json({ ok: true, evaluation, executed: false });
    }

    let upstream: Response;
    try {
      upstream = await fetch(body.url, {
        method: body.method,
        headers: body.headers,
        body: body.body,
      });
    } catch (e) {
      return c.json({ ok: false, evaluation, error: String(e) }, 502);
    }
    const text = await upstream.text();
    const output = inspectToolOutput(text, { tool: "http_request" });
    if (output.decision === "block") {
      return c.json(
        {
          ok: false,
          evaluation,
          output_dlp: output,
          status: upstream.status,
        },
        403,
      );
    }
    return c.json({
      ok: true,
      evaluation,
      output_dlp: output,
      status: upstream.status,
      body: output.result_redacted,
    });
  });

  app.get("/v1/sessions/:sessionId", (c) => {
    if (!requireApiKey(c)) return c.json({ error: "Unauthorized" }, 401);
    const agentId = c.req.query("agent_id");
    if (!agentId) return c.json({ error: "agent_id query required" }, 400);
    const session = getSession(agentId, c.req.param("sessionId"));
    if (!session) return c.json({ error: "Not found" }, 404);
    return c.json({ session });
  });

  app.delete("/v1/sessions/:sessionId", (c) => {
    if (!requireApiKey(c)) return c.json({ error: "Unauthorized" }, 401);
    const agentId = c.req.query("agent_id");
    if (!agentId) return c.json({ error: "agent_id query required" }, 400);
    clearSession(agentId, c.req.param("sessionId"));
    return c.json({ ok: true });
  });

  app.get("/v1/audit", (c) => {
    if (!requireApiKey(c)) return c.json({ error: "Unauthorized" }, 401);
    const limit = Number(c.req.query("limit") ?? 100);
    return c.json({ events: listAudit(limit) });
  });

  app.get("/v1/policies", (c) => {
    if (!requireApiKey(c)) return c.json({ error: "Unauthorized" }, 401);
    return c.json({ policy: engine.getPolicy() });
  });

  app.put("/v1/policies", async (c) => {
    if (!requireApiKey(c)) return c.json({ error: "Unauthorized" }, 401);
    const policy = await c.req.json();
    engine.setPolicy(policy);
    savePolicy(policy);
    return c.json({ ok: true, policy });
  });

  app.get("/v1/mcp/trust", (c) => {
    if (!requireApiKey(c)) return c.json({ error: "Unauthorized" }, 401);
    return c.json({ registry: engine.getMcpTrust() });
  });

  app.put("/v1/mcp/trust", async (c) => {
    if (!requireApiKey(c)) return c.json({ error: "Unauthorized" }, 401);
    const body = z
      .object({
        servers: z.array(
          z.object({
            server: z.string(),
            mode: z.enum(["observe", "pin"]),
            tools: z
              .array(
                z.object({
                  name: z.string(),
                  description_hash: z.string().optional(),
                  description: z.string().optional(),
                }),
              )
              .default([]),
          }),
        ),
      })
      .parse(await c.req.json());

    const registry = {
      servers: body.servers.map((s) => ({
        ...s,
        tools: s.tools.map((t) => ({
          name: t.name,
          description_hash:
            t.description_hash ??
            createHash("sha256")
              .update(`${s.server}\n${t.name}\n${t.description ?? ""}`)
              .digest("hex"),
          description: t.description,
        })),
      })),
    };
    engine.setMcpTrust(registry);
    saveMcpTrust(registry);
    return c.json({ ok: true, registry });
  });

  app.get("/v1/approvals", (c) => {
    if (!requireApiKey(c)) return c.json({ error: "Unauthorized" }, 401);
    expireStaleApprovals();
    return c.json({
      approvals: listApprovals().map((a) => ({
        ...a,
        resume_token_hash: undefined,
      })),
    });
  });

  app.post("/v1/approvals/:id/resolve", async (c) => {
    if (!requireApiKey(c)) return c.json({ error: "Unauthorized" }, 401);
    expireStaleApprovals();
    const id = c.req.param("id");
    const body = z
      .object({
        status: z.enum(["approved", "denied"]),
        note: z.string().optional(),
        resolved_by: z.string().optional(),
      })
      .parse(await c.req.json());
    const existing = getApproval(id);
    if (!existing) return c.json({ error: "Not found" }, 404);
    if (existing.status === "expired") {
      return c.json({ error: "Approval expired — denied by default" }, 410);
    }
    if (existing.status !== "pending") {
      return c.json({ error: `Approval already ${existing.status}` }, 409);
    }
    const updated = {
      ...existing,
      status: body.status,
      note: body.note,
      resolved_by: body.resolved_by ?? "api_key",
      resolved_at: new Date().toISOString(),
    };
    saveApproval(updated);
    appendAudit({
      id: `audit_${id}`,
      kind: "approval",
      agent_id: existing.agent_id,
      decision: body.status === "approved" ? "allow" : "block",
      risk_score: 0,
      explanation: `Approval ${body.status} by ${updated.resolved_by}${body.note ? `: ${body.note}` : ""}`,
      findings: [],
      approval_id: id,
      timestamp: updated.resolved_at!,
      result: body.status,
    });
    await dispatchWebhooks("approval.resolved", {
      ...updated,
      resume_token_hash: undefined,
    } as unknown as Record<string, unknown>);
    return c.json({
      approval: { ...updated, resume_token_hash: undefined },
      note:
        body.status === "approved"
          ? "Call POST /v1/approvals/:id/resume with resume_token + exact action to execute"
          : undefined,
    });
  });

  /** Bound resume: approved + matching action hash + one-time resume token. */
  app.post("/v1/approvals/:id/resume", async (c) => {
    if (!requireApiKey(c)) return c.json({ error: "Unauthorized" }, 401);
    expireStaleApprovals();
    const id = c.req.param("id");
    const body = z
      .object({
        resume_token: z.string().min(1),
        action: actionSchema,
        destination: z.string().optional(),
      })
      .parse(await c.req.json());

    const existing = getApproval(id);
    if (!existing) return c.json({ error: "Not found" }, 404);
    if (existing.status === "expired") {
      return c.json({ error: "Approval expired — denied by default", decision: "block" }, 410);
    }
    if (existing.status === "denied") {
      return c.json({ error: "Approval was denied", decision: "block" }, 403);
    }
    if (existing.status === "consumed") {
      return c.json({ error: "Resume token already consumed", decision: "block" }, 409);
    }
    if (existing.status !== "approved") {
      return c.json({ error: "Approval is not approved yet", status: existing.status }, 409);
    }
    if (!existing.resume_token_hash || hashToken(body.resume_token) !== existing.resume_token_hash) {
      return c.json({ error: "Invalid resume_token" }, 403);
    }
    const action_hash = hashAction(body.action, body.destination ?? body.action.destination);
    if (existing.action_hash && action_hash !== existing.action_hash) {
      return c.json(
        {
          error: "Action does not match the approved action_hash (bound approval)",
          expected: existing.action_hash,
          got: action_hash,
          decision: "block",
        },
        403,
      );
    }

    const updated = {
      ...existing,
      status: "consumed" as const,
      consumed_at: new Date().toISOString(),
    };
    saveApproval(updated);
    appendAudit({
      id: `resume_${id}`,
      kind: "approval",
      agent_id: existing.agent_id,
      decision: "allow",
      risk_score: 0,
      explanation: "Bound approval resumed — one-time token consumed",
      findings: [],
      approval_id: id,
      timestamp: updated.consumed_at!,
      result: "resumed",
    });

    return c.json({
      decision: "allow",
      human_approved: true,
      approval_id: id,
      action_hash,
      agent_id: existing.agent_id,
    });
  });

  app.get("/v1/webhooks", (c) => {
    if (!requireApiKey(c)) return c.json({ error: "Unauthorized" }, 401);
    return c.json({ webhooks: loadWebhooks() });
  });

  app.put("/v1/webhooks", async (c) => {
    if (!requireApiKey(c)) return c.json({ error: "Unauthorized" }, 401);
    const hooks = z
      .array(
        z.object({
          url: z.string().url(),
          events: z.array(z.string()).min(1),
          secret: z.string().optional(),
        }),
      )
      .parse(await c.req.json());
    saveWebhooks(hooks);
    return c.json({ ok: true, webhooks: hooks });
  });

  app.get("/v1/sessions", (c) => {
    if (!requireApiKey(c)) return c.json({ error: "Unauthorized" }, 401);
    return c.json({ sessions: listAllSessions().slice(0, 100) });
  });

  app.get("/v1/agents/:id/blast", (c) => {
    if (!requireApiKey(c)) return c.json({ error: "Unauthorized" }, 401);
    return c.json({ agent_id: c.req.param("id"), blast: engine.getBlastTracker().snapshot(c.req.param("id")) });
  });

  app.get("/v1/exports/siem", (c) => {
    if (!requireApiKey(c)) return c.json({ error: "Unauthorized" }, 401);
    if (!limits().siem_export) {
      return c.json(
        { error: "SIEM export requires Pro or higher", tier: tier(), upgrade: ["pro", "business", "enterprise"] },
        403,
      );
    }
    const limit = Number(c.req.query("limit") ?? 1000);
    return c.json({ events: exportAuditSiem(limit) });
  });

  app.get("/v1/exports/compliance.csv", (c) => {
    if (!requireApiKey(c)) return c.json({ error: "Unauthorized" }, 401);
    if (!limits().compliance_export) {
      return c.json(
        {
          error: "Compliance export requires Pro or higher",
          tier: tier(),
          upgrade: ["pro", "business", "enterprise"],
        },
        403,
      );
    }
    const limit = Number(c.req.query("limit") ?? 1000);
    const csv = exportAuditCsv(limit);
    return new Response(csv, {
      headers: {
        "content-type": "text/csv; charset=utf-8",
        "content-disposition": 'attachment; filename="agentfirewall-audit.csv"',
      },
    });
  });

  app.post("/v1/maintenance/prune-audit", (c) => {
    if (!requireApiKey(c)) return c.json({ error: "Unauthorized" }, 401);
    const result = pruneAudit(limits().audit_retention_days);
    return c.json({ ok: true, retention_days: limits().audit_retention_days, ...result });
  });

  // ——— Public signup (Developer) + Billing (Stripe) ———
  app.get("/v1/billing/plans", (c) => {
    const plans = getBillingPlans();
    return c.json({
      product: "agentfirewall",
      currency: "usd",
      plans: plans.map((p) => ({
        ...p,
        checkout_ready: Boolean(p.stripe_price_id) || p.id === "developer",
      })),
    });
  });

  app.get("/v1/billing/entitlement", (c) => {
    if (!requireApiKey(c)) return c.json({ error: "Unauthorized" }, 401);
    const cust = currentCustomer();
    if (cust) {
      return c.json({
        entitlement: {
          plan_id: cust.plan_id,
          tier: cust.tier,
          status: cust.status,
          email: cust.email,
          customer_id: cust.id,
        },
        effective_tier: tier(),
      });
    }
    return c.json({ entitlement: loadEntitlement(), effective_tier: tier() });
  });

  /** Free Developer API key — emailed + returned once. */
  app.post("/v1/signup", async (c) => {
    const body = z
      .object({
        email: z.string().email().max(200),
        name: z.string().min(1).max(120).optional(),
        website: z.string().max(200).optional(),
      })
      .parse(await c.req.json());
    if (body.website?.trim()) {
      return c.json({ ok: true, message: "Check your email for your API key." });
    }
    if (!signupRateOk(clientIp(c), 8)) {
      return c.json({ error: "Too many signups from this IP — try again later" }, 429);
    }
    const existing = findCustomerByEmail(body.email);
    if (existing && existing.plan_id !== "developer") {
      return c.json(
        {
          error: "This email already has a paid plan — use Stripe Customer Portal or contact support",
          plan: existing.plan_id,
        },
        409,
      );
    }
    const { customer, api_key } = issueCustomer({
      email: body.email,
      name: body.name,
      plan_id: "developer",
      tier: "developer",
      status: "active",
      existing: existing,
    });
    await deliverApiKeyEmail({ email: customer.email, apiKey: api_key, plan: "Developer" });
    return c.json({
      ok: true,
      plan: "developer",
      tier: "developer",
      api_key,
      customer_id: customer.id,
      message: "API key issued. Store it now — it is also emailed to you.",
      api_base: apiPublicBase(new URL(c.req.url).origin),
    });
  });

  /** Public or authenticated Checkout — no API key required when email is provided. */
  app.post("/v1/billing/checkout", async (c) => {
    const body = z
      .object({
        plan: z.enum(["pro", "business", "enterprise"]),
        success_url: z.string().url().optional(),
        cancel_url: z.string().url().optional(),
        email: z.string().email().optional(),
      })
      .parse(await c.req.json());

    const cust = currentCustomer();
    const email = body.email ?? cust?.email;
    if (!email && !requireApiKey(c)) {
      return c.json({ error: "email required for public checkout" }, 400);
    }
    if (!email) {
      return c.json({ error: "email required" }, 400);
    }
    if (!signupRateOk(clientIp(c), 12)) {
      return c.json({ error: "Too many checkout attempts — try again later" }, 429);
    }

    const site = publicSiteBase();
    const successUrl =
      body.success_url ??
      `${site}/success.html?session_id={CHECKOUT_SESSION_ID}`;
    const cancelUrl = body.cancel_url ?? `${site}/?billing=cancel`;

    try {
      const session = await createCheckoutSession({
        planId: body.plan,
        successUrl,
        cancelUrl,
        customerEmail: email,
        clientReferenceId: cust?.id ?? email,
      });
      return c.json({
        ok: true,
        url: session.url,
        session_id: session.id,
        plan: planById(body.plan),
      });
    } catch (e) {
      return c.json({ error: String(e instanceof Error ? e.message : e) }, 400);
    }
  });

  /** One-time API key reveal after Stripe Checkout (also emailed). */
  app.get("/v1/billing/reveal", async (c) => {
    const sessionId = c.req.query("session_id");
    if (!sessionId?.startsWith("cs_")) {
      return c.json({ error: "session_id required" }, 400);
    }
    try {
      const session = await retrieveCheckoutSession(sessionId);
      const paymentStatus = String(session.payment_status ?? "");
      const status = String(session.status ?? "");
      if (paymentStatus !== "paid" && status !== "complete") {
        return c.json({ error: "Checkout not paid yet", payment_status: paymentStatus, status }, 402);
      }
      const reveal = consumeKeyReveal(sessionId);
      if (reveal) {
        return c.json({
          ok: true,
          api_key: reveal.api_key,
          email: reveal.email,
          plan: reveal.plan_id,
          customer_id: reveal.customer_id,
          message: "Store this API key now — it will not be shown again.",
          api_base: apiPublicBase(new URL(c.req.url).origin),
        });
      }
      // Webhook may be slightly behind — synthesize from session metadata if needed
      const meta = (session.metadata ?? {}) as Record<string, string>;
      const email = String(
        session.customer_email ??
          (session.customer_details as { email?: string } | undefined)?.email ??
          "",
      );
      const planId = (meta.planId as PlanId) || "pro";
      if (!email.includes("@")) {
        return c.json({ error: "Key not ready yet — check email or retry in a few seconds" }, 409);
      }
      const plan = planById(planId) ?? planById("pro")!;
      const existing =
        findCustomerByEmail(email) ||
        (typeof session.customer === "string"
          ? findCustomerByStripeCustomer(session.customer)
          : undefined);
      const { customer, api_key } = issueCustomer({
        email,
        plan_id: plan.id,
        tier: plan.tier,
        status: "active",
        stripe_customer_id: typeof session.customer === "string" ? session.customer : undefined,
        stripe_subscription_id:
          typeof session.subscription === "string" ? session.subscription : undefined,
        existing,
      });
      applySubscriptionEvent({
        planId: plan.id,
        customerId: customer.stripe_customer_id,
        subscriptionId: customer.stripe_subscription_id,
        status: "active",
      });
      await deliverApiKeyEmail({ email: customer.email, apiKey: api_key, plan: plan.name });
      return c.json({
        ok: true,
        api_key,
        email: customer.email,
        plan: plan.id,
        customer_id: customer.id,
        message: "Store this API key now — it will not be shown again.",
        api_base: apiPublicBase(new URL(c.req.url).origin),
      });
    } catch (e) {
      return c.json({ error: String(e instanceof Error ? e.message : e) }, 400);
    }
  });

  app.post("/v1/billing/webhook", async (c) => {
    const payload = await c.req.text();
    const whsec = process.env.STRIPE_WEBHOOK_SECRET ?? "";
    const sig = c.req.header("stripe-signature");
    if (!whsec) {
      return c.json({ error: "Webhook secret not configured" }, 503);
    }
    if (!verifyStripeWebhook(payload, sig, whsec)) {
      return c.json({ error: "Invalid signature" }, 400);
    }
    const event = JSON.parse(payload) as {
      type: string;
      data: { object: Record<string, unknown> };
    };
    const obj = event.data.object;

    if (event.type === "checkout.session.completed") {
      const meta = (obj.metadata ?? {}) as Record<string, string>;
      const planId = (meta.planId as PlanId) || "pro";
      const plan = planById(planId) ?? planById("pro")!;
      const email = String(
        obj.customer_email ??
          (obj.customer_details as { email?: string } | undefined)?.email ??
          "",
      );
      if (email.includes("@")) {
        const existing =
          findCustomerByEmail(email) ||
          (typeof obj.customer === "string" ? findCustomerByStripeCustomer(obj.customer) : undefined);
        const { customer, api_key } = issueCustomer({
          email,
          plan_id: plan.id,
          tier: plan.tier,
          status: "active",
          stripe_customer_id: typeof obj.customer === "string" ? obj.customer : undefined,
          stripe_subscription_id: typeof obj.subscription === "string" ? obj.subscription : undefined,
          existing,
        });
        const sessionId = String(obj.id ?? "");
        if (sessionId.startsWith("cs_")) {
          saveKeyReveal({
            session_id: sessionId,
            customer_id: customer.id,
            api_key,
            email: customer.email,
            plan_id: plan.id,
            expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
          });
        }
        await deliverApiKeyEmail({ email: customer.email, apiKey: api_key, plan: plan.name });
      }
      applySubscriptionEvent({
        planId,
        customerId: obj.customer as string | undefined,
        subscriptionId: obj.subscription as string | undefined,
        status: "active",
      });
    }
    if (
      event.type === "customer.subscription.updated" ||
      event.type === "customer.subscription.created"
    ) {
      const meta = (obj.metadata ?? {}) as Record<string, string>;
      const items = obj.items as { data?: Array<{ price?: { id?: string } }> } | undefined;
      const priceId = items?.data?.[0]?.price?.id;
      const statusRaw = String(obj.status ?? "");
      const status =
        statusRaw === "active" || statusRaw === "trialing"
          ? "active"
          : statusRaw === "past_due"
            ? "past_due"
            : "canceled";
      applySubscriptionEvent({
        planId: meta.planId,
        priceId,
        customerId: obj.customer as string | undefined,
        subscriptionId: obj.id as string | undefined,
        status: status as "active" | "past_due" | "canceled",
      });
      if (typeof obj.customer === "string") {
        const cust = findCustomerByStripeCustomer(obj.customer);
        if (cust) {
          const plan = meta.planId ? planById(meta.planId) : planById(cust.plan_id);
          if (plan) {
            updateCustomerBilling(cust.id, {
              plan_id: plan.id,
              tier: plan.tier,
              status: status === "canceled" ? "canceled" : status,
              stripe_subscription_id: String(obj.id),
            });
          }
        }
      }
    }
    if (event.type === "customer.subscription.deleted") {
      applySubscriptionEvent({
        customerId: obj.customer as string | undefined,
        subscriptionId: obj.id as string | undefined,
        status: "canceled",
      });
      if (typeof obj.customer === "string") {
        const cust = findCustomerByStripeCustomer(obj.customer);
        if (cust) {
          updateCustomerBilling(cust.id, {
            plan_id: "developer",
            tier: "developer",
            status: "canceled",
          });
        }
      }
    }
    return c.json({ received: true });
  });

  app.get("/v1/contact/status", (c) => {
    const cfg = contactConfigured();
    return c.json({
      ok: cfg.resend && cfg.inbox,
      configured: cfg,
      // Never expose the private inbox address
      public_from: cfg.from,
    });
  });

  app.post("/v1/contact", async (c) => {
    const body = z
      .object({
        name: z.string().min(1).max(120),
        email: z.string().email().max(200),
        company: z.string().max(200).optional(),
        message: z.string().min(10).max(5000),
        website: z.string().max(200).optional(),
      })
      .parse(await c.req.json());
    const result = await sendContactEmail(body, { ip: clientIp(c) });
    if (!result.ok) return c.json({ error: result.error }, result.status as 400 | 429 | 502 | 503);
    return c.json({ ok: true, message: "Message sent — we'll get back to you." });
  });

  return app;
}
