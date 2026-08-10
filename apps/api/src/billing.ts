/**
 * AgentFirewall billing catalog + Stripe Checkout + webhook → tier entitlement.
 */
import { createHmac, timingSafeEqual } from "crypto";
import type { Tier } from "@agentfirewall/core";
import fs from "fs";
import path from "path";
import { dataDirPath } from "./store.js";

export interface BillingPlan {
  id: "developer" | "pro" | "business" | "enterprise";
  name: string;
  price_usd_month: number;
  stripe_price_id: string | null;
  tier: Tier;
  description: string;
  features: string[];
}

export function getBillingPlans(): BillingPlan[] {
  return [
    {
      id: "developer",
      name: "Developer",
      price_usd_month: 0,
      stripe_price_id: null,
      tier: "developer",
      description: "Get started — fail-closed agent firewall for local/dev",
      features: ["5k evaluations/day", "5 agents", "7-day audit", "Core detectors"],
    },
    {
      id: "pro",
      name: "Pro",
      price_usd_month: 129,
      stripe_price_id: process.env.STRIPE_PRICE_PRO ?? null,
      tier: "pro",
      description: "Production agents with SIEM + compliance export",
      features: [
        "50k evaluations/day",
        "25 agents",
        "30-day audit",
        "SIEM + compliance CSV",
        "Egress allowlists + bound approvals",
      ],
    },
    {
      id: "business",
      name: "Business",
      price_usd_month: 599,
      stripe_price_id: process.env.STRIPE_PRICE_BUSINESS ?? null,
      tier: "business",
      description: "Team scale with SSO/RBAC readiness",
      features: [
        "250k evaluations/day",
        "100 agents",
        "90-day audit",
        "SSO + RBAC flags",
        "Priority support path",
      ],
    },
    {
      id: "enterprise",
      name: "Enterprise",
      price_usd_month: 2499,
      stripe_price_id: process.env.STRIPE_PRICE_ENTERPRISE ?? null,
      tier: "enterprise",
      description: "Unlimited + private networking (starting list price)",
      features: [
        "Unlimited evaluations",
        "Unlimited agents",
        "365-day audit",
        "Private networking",
        "Custom contract available",
      ],
    },
  ];
}

/** Prefer getBillingPlans() so price IDs refresh from env. */
export const BILLING_PLANS = getBillingPlans();

export interface BillingEntitlement {
  customer_id?: string;
  subscription_id?: string;
  plan_id: BillingPlan["id"];
  tier: Tier;
  status: "active" | "canceled" | "past_due" | "none";
  updated_at: string;
}

function billingPath(): string {
  return path.join(dataDirPath(), "billing.json");
}

export function loadEntitlement(): BillingEntitlement {
  try {
    const p = billingPath();
    if (fs.existsSync(p)) {
      return JSON.parse(fs.readFileSync(p, "utf8")) as BillingEntitlement;
    }
  } catch {
    /* ignore */
  }
  return {
    plan_id: "developer",
    tier: (process.env.AGENTFIREWALL_TIER as Tier) || "developer",
    status: "none",
    updated_at: new Date().toISOString(),
  };
}

export function saveEntitlement(e: BillingEntitlement): void {
  fs.mkdirSync(dataDirPath(), { recursive: true });
  fs.writeFileSync(billingPath(), JSON.stringify(e, null, 2));
}

export function planFromPriceId(priceId: string): BillingPlan | undefined {
  return getBillingPlans().find((p) => p.stripe_price_id && p.stripe_price_id === priceId);
}

export function planById(id: string): BillingPlan | undefined {
  return getBillingPlans().find((p) => p.id === id);
}

async function stripeForm(
  secret: string,
  method: string,
  apiPath: string,
  form?: Record<string, string>,
) {
  const res = await fetch(`https://api.stripe.com/v1${apiPath}`, {
    method,
    headers: {
      Authorization: `Bearer ${secret}`,
      ...(form ? { "Content-Type": "application/x-www-form-urlencoded" } : {}),
    },
    body: form ? new URLSearchParams(form).toString() : undefined,
  });
  const json = (await res.json()) as Record<string, unknown>;
  if (!res.ok) {
    const err = json.error as { message?: string } | undefined;
    throw new Error(err?.message || `Stripe ${res.status}`);
  }
  return json;
}

export async function createCheckoutSession(opts: {
  planId: string;
  successUrl: string;
  cancelUrl: string;
  customerEmail?: string;
  clientReferenceId?: string;
}): Promise<{ url: string; id: string }> {
  const secret = process.env.STRIPE_SECRET_KEY;
  if (!secret?.startsWith("sk_")) {
    throw new Error("STRIPE_SECRET_KEY not configured");
  }
  const plan = planById(opts.planId);
  if (!plan || plan.id === "developer") {
    throw new Error("Choose pro, business, or enterprise");
  }
  if (!plan.stripe_price_id) {
    throw new Error(`Stripe price not configured for ${plan.id} — run Amber ensure script`);
  }

  const form: Record<string, string> = {
    mode: "subscription",
    success_url: opts.successUrl,
    cancel_url: opts.cancelUrl,
    "line_items[0][price]": plan.stripe_price_id,
    "line_items[0][quantity]": "1",
    "metadata[product]": "agentfirewall",
    "metadata[planId]": plan.id,
    "metadata[tier]": plan.tier,
    "subscription_data[metadata][product]": "agentfirewall",
    "subscription_data[metadata][planId]": plan.id,
    "subscription_data[metadata][tier]": plan.tier,
    allow_promotion_codes: "true",
  };
  if (opts.customerEmail) form.customer_email = opts.customerEmail;
  if (opts.clientReferenceId) form.client_reference_id = opts.clientReferenceId;

  const session = await stripeForm(secret, "POST", "/checkout/sessions", form);
  return { url: session.url as string, id: session.id as string };
}

export async function retrieveCheckoutSession(sessionId: string): Promise<Record<string, unknown>> {
  const secret = process.env.STRIPE_SECRET_KEY;
  if (!secret?.startsWith("sk_")) {
    throw new Error("STRIPE_SECRET_KEY not configured");
  }
  return stripeForm(secret, "GET", `/checkout/sessions/${sessionId}`);
}

/** Verify Stripe-Signature header (webhook). */
export function verifyStripeWebhook(
  payload: string,
  header: string | undefined,
  secret: string,
): boolean {
  if (!header || !secret) return false;
  const parts = Object.fromEntries(
    header.split(",").map((p) => {
      const [k, v] = p.split("=");
      return [k.trim(), v];
    }),
  );
  const t = parts.t;
  const v1 = parts.v1;
  if (!t || !v1) return false;
  const signed = createHmac("sha256", secret).update(`${t}.${payload}`).digest("hex");
  try {
    return timingSafeEqual(Buffer.from(signed), Buffer.from(v1));
  } catch {
    return false;
  }
}

export function applySubscriptionEvent(opts: {
  planId?: string;
  priceId?: string;
  customerId?: string;
  subscriptionId?: string;
  status: BillingEntitlement["status"];
}): BillingEntitlement {
  let plan =
    (opts.planId ? planById(opts.planId) : undefined) ||
    (opts.priceId ? planFromPriceId(opts.priceId) : undefined);
  if (!plan && opts.status === "canceled") {
    plan = planById("developer");
  }
  if (!plan) plan = planById("developer")!;

  const ent: BillingEntitlement = {
    customer_id: opts.customerId,
    subscription_id: opts.subscriptionId,
    plan_id: plan.id,
    tier: plan.tier,
    status: opts.status === "canceled" ? "canceled" : opts.status,
    updated_at: new Date().toISOString(),
  };
  if (opts.status === "canceled") {
    ent.plan_id = "developer";
    ent.tier = "developer";
  }
  saveEntitlement(ent);
  return ent;
}
