# Amber hosting task — AgentFirewall

**Task ID:** `cmsmirrr30003tbe845tv3nnk`
**Status:** READY
**Assignee:** CURSOR / Amber

OWNER AUTHORIZATION (Michael — 2026-08-10):
- Amber has already bought hosting and DNS for nine of Michael's websites on Launch Ready.
- Michael owns Launch Ready. Amber MUST provision AgentFirewall herself end-to-end.
- DO NOT ask Michael to create Hetzner/Fly/Railway accounts or paste new tokens.
- Use credentials already in Amber Vault / Launch Ready / Railway CLI session.
- Prefer the same path used for the existing nine sites (Launch Ready hosting purchase + DNS).
- If that path is Cloudflare Pages (static), ALSO ensure the Node API is live (reuse/rename Railway capacity like MarketIntel/SchemaFetch if free-plan service limit blocks a new service — Amber decides; owner authorizes reuse of idle capacity if needed).
- Wholesale/owner COGS only — do NOT force Michael through retail $49 customer checkout UI unless that is literally how the nine sites were bought (then use owner/admin zero-charge or vault Stripe).

PRODUCT:
- Repo: C:/Users/michael/Documents/agentfirewall
- Docker API: Dockerfile (port 8787, AGENTFIREWALL_DATA=/app/.data)
- Dashboard: apps/dashboard (static build can sit on Pages; API must be Node)
- Target hostname: agentfirewall.launchreadyal.com (Cloudflare zone launchreadyal.com)
- Stripe + Resend already in product .env locally — inject to host secrets
- Contact form needs AGENTFIREWALL_CONTACT_TO on host (OWNER_EMAIL / SUPPORT inbox from vault if present)

DELIVERABLE:
- Live https://agentfirewall.launchreadyal.com (or reported URL) with SSL
- DNS records created
- /health 200 on API (same host or api.agentfirewall… / path proxy — document which)
- Write C:/Users/michael/Documents/agentfirewall/docs/AMBER-HOSTING-HANDOFF-RESULT.md
