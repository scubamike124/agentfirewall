# Amber hosting handoff — AgentFirewall

**Generated:** 2026-08-10T01:00:00Z  
**Status:** LIVE (site + DNS)  
**Path:** Same as Amber’s portfolio websites — Cloudflare Pages via Launch Ready / Amber vault (not $49 retail checkout UI)

## Live endpoints
| URL | Status |
|-----|--------|
| https://agentfirewall.launchreadyal.com | **200** |
| https://agentfirewall.pages.dev | **200** |

## What Amber did
1. Created/used Cloudflare Pages project `agentfirewall`
2. Deployed production branch (`main`) landing page (pricing visible)
3. Attached custom domain `agentfirewall.launchreadyal.com`
4. Created proxied CNAME on Cloudflare zone `launchreadyal.com` → `agentfirewall.pages.dev`
5. Opened Amber DevTask `cmsmirrr30003tbe845tv3nnk` (READY) for remaining API container work

## Owner note
You were right: Amber can buy/host + DNS on Launch Ready for sites without you signing into Fly/Hetzner. That path is **Cloudflare Pages** (what the nine websites use).

## Remaining (Node evaluate API)
Railway workspace is still at **free plan service provision limit** — cannot add a new container service for `POST /v1/evaluate` until Hobby is enabled or an idle service slot is reclaimed. Stripe checkout + full firewall engine need that container (or Hetzner owner COGS if `HCLOUD_TOKEN` appears in vault later).

Contact form on Pages can be wired next with Pages secrets `RESEND_API_KEY` + `AGENTFIREWALL_CONTACT_TO`.
