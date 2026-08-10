# AgentFirewall phases

One product. Six core systems. Same API for Developer → Enterprise.

## Phase status

| Phase | System | Status |
|-------|--------|--------|
| 1 | Agent Identity — short-lived credentials, scopes, attribution | **Done** |
| 2 | Runtime Action Control — tool/destination/amount inspection | **Done** |
| 3 | Prompt Injection & MCP/Tool Poisoning Defense | **Done** |
| 4 | Behavior & Trajectory Detection (server-side sessions) | **Done** |
| 5 | Secrets & Data-Loss Protection | **Done** |
| 6 | Audit & Forensics (+ SIEM/compliance exports by tier) | **Done** |

## MVP checklist

- [x] `POST /v1/evaluate`
- [x] `POST /v1/trajectory/evaluate`
- [x] Policy engine + configurable rules
- [x] allow / block / approval_required
- [x] MCP/tool inspection
- [x] Prompt-injection detection
- [x] Secret leakage detection
- [x] Full audit logs
- [x] Dashboard
- [x] JS/TS + Python SDKs
- [x] Webhooks for alerts & approvals
- [x] OpenAPI
- [x] Docker + CI

## Hardening (post-MVP)

| Control | Status |
|---------|--------|
| Fail-closed agent credentials (`agent_token` required) | **Done** |
| Per-agent egress allowlists (`AGENTFIREWALL_EGRESS_MODE`) | **Done** |
| Bound approvals (action hash + one-time resume; timeout=deny) | **Done** |
| Output / tool-result DLP (`POST /v1/inspect/output`) | **Done** |
| MCP supply-chain trust (pin / first-seen / drift) | **Done** |
| Untrusted-content gate for high-impact tools | **Done** |
| Non-bypassable HTTP gate (`POST /v1/gate/http`) | **Done** |
| Per-agent blast-radius caps | **Done** |

Env:
- `AGENTFIREWALL_REQUIRE_AGENT_TOKEN=1` (default) — set `0` only for local demos
- `AGENTFIREWALL_EGRESS_MODE=off|observe|enforce` (default `observe`)

## Enterprise (same core — tier gated)

Configured via `AGENTFIREWALL_TIER=developer|pro|business|enterprise`:

| Capability | Dev | Pro | Business | Enterprise |
|------------|-----|-----|----------|------------|
| Evaluations/day | 5k | 50k | 250k | unlimited |
| Audit retention | 7d | 30d | 90d | 365d |
| SIEM export | — | ✓ | ✓ | ✓ |
| Compliance CSV | — | ✓ | ✓ | ✓ |
| SSO / RBAC / private net | — | — | SSO+RBAC | all |

SSO, private networking, and full RBAC UIs are extension points on this core (not separate products).

## Metering

Usage is measured by **security evaluations** (`GET /v1/meta` → `usage`).

Tier: set `AGENTFIREWALL_TIER=developer|pro|business|enterprise` (default `developer`).
