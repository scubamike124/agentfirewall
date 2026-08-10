# AgentFirewall

**Real-time AI Agent Security Firewall** — model-agnostic protection for autonomous agents, MCP, tool calls, and API actions.

```
Agent → Security Firewall → Policy Engine → ALLOW | BLOCK | REQUIRE HUMAN APPROVAL → Tool/API
```

**Live**
- Product site: https://agentfirewall.launchreadyal.com
- Security proof (public): https://agentfirewall.launchreadyal.com/security-proof
- Production API: https://api.agentfirewall.launchreadyal.com
- OpenAPI: https://api.agentfirewall.launchreadyal.com/v1/openapi.json

This is **not** a vulnerability scanner. It evaluates **actions before execution**, tracks **multi-step trajectories**, blocks **secret leakage** and **prompt injection**, and supports **human approval gates**.

## Security proof (production)

Latest first-party adversarial suite against the live enforcement API (`proof_2026-08-10T01-54-56-114Z`):

| Metric | Result |
|--------|------:|
| Attack hold | **67/67 (100%)** |
| False positives | **0/1000 (0.00%)** |
| Secret exfiltration | 20/20 |
| Bypass variants | 22/22 |
| Latency p50 / p95 | 62.4 / 87.1 ms |
| Approval / fail-safe / audit | YES / YES / 50/50 |

Earlier production run was **54/62 (87.1%)** with secrets at **46.7%**. The firewall was hardened (encodings, fragmentation, GitHub/Slack/password policy); the test cases were not weakened. Full report: [proofs/results/latest.md](proofs/results/latest.md) · [public page](https://agentfirewall.launchreadyal.com/security-proof).

> First-party controlled suite — not a third-party pentest. Rates are corpus-bound, not a claim of universal protection.

## Five-minute onboarding

```bash
npm install
npm run build -w @agentfirewall/core
npm run dev
# API: http://localhost:8787
# Default API key: af_dev_key_change_me
```

Dashboard (optional):

```bash
npm run dev -w @agentfirewall/dashboard
# http://localhost:5173
```

### Protect a tool call (TypeScript)

```ts
import { AgentFirewallClient } from "@agentfirewall/sdk";

const fw = new AgentFirewallClient({
  apiKey: "af_dev_key_change_me",
  agentId: "my-agent",
  baseUrl: "http://localhost:8787",
});
await fw.issueCredential({ egress_allowlist: ["*.example.com"] });

const secureFetch = fw.wrapTool("http_request", async (args: { url: string }) => {
  return fetch(args.url).then((r) => r.text());
});

await secureFetch({ url: "https://example.com" });
// Or force HTTP through the gate: await fw.gatedFetch("https://example.com");
```

### Python

```bash
pip install -e sdks/python
```

```python
from agentfirewall import AgentFirewallClient

fw = AgentFirewallClient(api_key="af_dev_key_change_me", agent_id="my-agent")
fw.issue_credential(egress_allowlist=["*.example.com"])
fw.evaluate(tool="shell", parameters={"command": "ls"})  # raises if blocked / needs approval
```

## Core API

### `POST /v1/evaluate`

Evaluate a single proposed action (tool/MCP/API). **Requires `agent_token`** (fail-closed) unless `AGENTFIREWALL_REQUIRE_AGENT_TOKEN=0`.

```json
{
  "agent": { "agent_id": "research-bot" },
  "agent_token": "af_…",
  "action": {
    "type": "tool_call",
    "tool": "http_request",
    "parameters": { "url": "https://example.com" },
    "destination": "https://example.com"
  },
  "context": {
    "session_id": "sess_1",
    "untrusted_content": ["page text…"],
    "mcp_descriptions": ["tool description…"]
  }
}
```

Response:

```json
{
  "decision": "allow",
  "risk_score": 12,
  "risk_level": "low",
  "explanation": "…",
  "findings": [],
  "evaluation_id": "eval_…",
  "action_hash": "…"
}
```

Decisions: `allow` | `block` | `approval_required`.  
When `approval_required`, response includes `approval_id`, `resume_token`, and `action_hash`. After human approve, call `POST /v1/approvals/:id/resume` with the same action (timeout = deny).

### `POST /v1/trajectory/evaluate`

Evaluate the **sequence** of actions (major differentiator). Individually harmless steps can become dangerous together.

Pass `session_id` on `/v1/evaluate` and the API remembers the session trajectory server-side (no need to resend full history). Inspect with `GET /v1/sessions/:sessionId?agent_id=…`.

### Other endpoints

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/v1/agents` | Issue short-lived agent credential |
| PUT | `/v1/agents/:id/egress` | Set egress allowlist |
| POST | `/v1/inspect/output` | Output / tool-result DLP |
| POST | `/v1/gate/http` | Non-bypassable HTTP gate (+ optional fetch) |
| GET/PUT | `/v1/mcp/trust` | MCP server/tool pin registry |
| GET | `/v1/audit` | Forensics / audit log |
| GET | `/v1/sessions/:id?agent_id=` | Inspect server-side session trajectory |
| DELETE | `/v1/sessions/:id?agent_id=` | Clear a session |
| GET/PUT | `/v1/policies` | Configurable policy rules |
| GET | `/v1/approvals` | Pending human approvals |
| POST | `/v1/approvals/:id/resolve` | Approve or deny |
| POST | `/v1/approvals/:id/resume` | Bound one-time resume after approve |
| GET/PUT | `/v1/webhooks` | Alert + approval webhooks |

Auth: `Authorization: Bearer <API_KEY>` or `x-api-key`.

## Six systems + hardening

1. **Agent Identity** — fail-closed short-lived credentials
2. **Runtime Action Control** — tool/destination/amount + egress allowlists
3. **Prompt Injection / Tool Poisoning** — scans + untrusted-content gates + MCP trust pins
4. **Behavior / Trajectory** — multi-step pattern detection
5. **Secrets / DLP** — params + **tool output** scanning
6. **Audit / Forensics** — full decision trail with redacted parameters

Also: bound approvals, blast-radius caps, `POST /v1/gate/http` enforcement gate.

## Monorepo layout

```
packages/core     Policy engine + detectors + trajectory
packages/sdk      JavaScript/TypeScript SDK
apps/api          REST API (Hono)
apps/dashboard    Simple ops UI
sdks/python       Python SDK
```

## Configuration

| Env | Default | Meaning |
|-----|---------|---------|
| `AGENTFIREWALL_API_KEY` | `af_dev_key_change_me` | Customer API key |
| `AGENTFIREWALL_DATA` | `./.data` | Policy, audit, approvals, webhooks, agents |
| `AGENTFIREWALL_TIER` | `developer` | `developer` \| `pro` \| `business` \| `enterprise` |
| `AGENTFIREWALL_REQUIRE_AGENT_TOKEN` | `1` | Fail-closed identity (`0` to disable) |
| `AGENTFIREWALL_EGRESS_MODE` | `observe` | `off` \| `observe` \| `enforce` |
| `PORT` | `8787` | API port |

## Pricing direction

| Plan | Price | Stripe |
|------|-------|--------|
| Developer | Free | — |
| Pro | $129/mo | `STRIPE_PRICE_PRO` |
| Business | $599/mo | `STRIPE_PRICE_BUSINESS` |
| Enterprise | $2,499/mo list | `STRIPE_PRICE_ENTERPRISE` |

Checkout: `POST /v1/billing/checkout` · Plans: `GET /v1/billing/plans` · Webhook: `POST /v1/billing/webhook`  
Catalog lives on the shared Amber Stripe account (`metadata.product=agentfirewall`). Details: [docs/STRIPE-PRICING.md](docs/STRIPE-PRICING.md).

## Tests

```bash
npm test
npm run example   # needs API running
```

OpenAPI: `GET /v1/openapi.json`  
Meta / usage / tier: `GET /v1/meta`  
SIEM export (Pro+): `GET /v1/exports/siem`  
Compliance CSV (Pro+): `GET /v1/exports/compliance.csv`

Phases: [docs/PHASES.md](docs/PHASES.md)

```bash
docker compose up --build -d
```
