# Contact email (Resend)

Public visitors never see your personal address.

| Env | Purpose |
|-----|---------|
| `RESEND_API_KEY` | From Amber Vault |
| `AGENTFIREWALL_MAIL_FROM` | Public From, e.g. `AgentFirewall <noreply@yourdomain.com>` |
| `AGENTFIREWALL_CONTACT_TO` | **Your private inbox** — only on the server |

## API

- `GET /v1/contact/status` — whether delivery is configured (does not reveal inbox)
- `POST /v1/contact` — `{ name, email, company?, message }` → Resend → your inbox (`reply_to` = visitor)

Rate limit: 5 messages / 15 min / IP. Honeypot field `website` drops bots silently.

## Amber

```bash
npx tsx scripts/agentfirewall-ensure-resend.ts
```

Then set your inbox once:

```bash
# in agentfirewall/.env
AGENTFIREWALL_CONTACT_TO=you@your-inbox.com
```
