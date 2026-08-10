# AgentFirewall hosting status

**Updated:** 2026-08-10  
**Actor:** Cursor agent + Amber vault/DNS tooling

## Blocker (purchase not completed)

| Path | Status | Why |
|------|--------|-----|
| Launch Ready **owner wholesale** (Hetzner CX23 ≈ **$5.98/mo** COGS) | **Blocked** | Vault missing `HCLOUD_TOKEN`. Admin UI: `/admin/app-hosting` on launchreadyal.com |
| Launch Ready **retail** hosting ($49/mo) | **Wrong SKU** | Provisions Cloudflare Pages — fine for static sites, **not** a Node API + volume |
| Railway new service | **Blocked** | `Free plan resource provision limit exceeded` on workspace `scubamike124's Projects` (already running amber-hq + schemafetch services) |

## Ready when unblocked

- Docker image: repo `Dockerfile` (API on `:8787`, data at `/app/.data`)
- DNS script (Cloudflare → `agentfirewall.launchreadyal.com`):  
  `npx tsx scripts/agentfirewall-cf-dns.ts <railway-or-hetzner-host>`  
  (from amberAI manager)
- Stripe + Resend env already in local `.env` (gitignored)

## Recommended owner action (pick one)

1. **Preferred (Launch Ready wholesale):** Create a Hetzner Cloud project + payment method + Read/Write API token → store as `HCLOUD_TOKEN` in Amber Vault → set `HCLOUD_DRY_RUN=0` → tell Amber/agent to provision `agentfirewall` with `confirmSpend=true` and hostname `agentfirewall.launchreadyal.com`.
2. **Alternative:** Upgrade Railway workspace past free service limit → agent creates `agentfirewall` service, volume `/app/.data`, custom domain + Cloudflare CNAME.
3. **Not recommended:** Buy $49 Launch Ready “website hosting” for this product (Pages can’t run the firewall API).

## Intended live URLs

| URL | Role |
|-----|------|
| `https://agentfirewall.launchreadyal.com` | Public API (+ later dashboard) |
| Railway/Hetzner service URL | Origin behind Cloudflare proxy |

## Contact email note

`RESEND_API_KEY` is configured. Still need `AGENTFIREWALL_CONTACT_TO=<your inbox>` in `.env` / host secrets so the contact form can deliver.
