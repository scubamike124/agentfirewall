# AgentFirewall Stripe pricing

Shared Amber Stripe account: `acct_1OWJRDKDbVMTgaXy`

| Plan | Price | Stripe Price ID |
|------|-------|-----------------|
| Developer | Free | — |
| Pro | $129/mo | `price_1U2hINKDbVMTgaXyXH5l4gyG` |
| Business | $599/mo | `price_1U2hINKDbVMTgaXyA7fKpxVb` |
| Enterprise | $2,499/mo (list) | `price_1U2hIOKDbVMTgaXypNLg9Jr5` |

Products metadata: `product=agentfirewall`.

Checkout: `POST /v1/billing/checkout` with `{ "plan": "pro"|"business"|"enterprise" }`.
