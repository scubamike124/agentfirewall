/**
 * Multi-tenant customers + API keys (persisted under AGENTFIREWALL_DATA).
 */
import { createHash, randomBytes } from "crypto";
import fs from "fs";
import path from "path";
import type { Tier } from "@agentfirewall/core";
import { dataDirPath } from "./store.js";

export type PlanId = "developer" | "pro" | "business" | "enterprise";

export interface Customer {
  id: string;
  email: string;
  name?: string;
  plan_id: PlanId;
  tier: Tier;
  status: "active" | "past_due" | "canceled" | "none";
  api_key_hash: string;
  api_key_prefix: string;
  stripe_customer_id?: string;
  stripe_subscription_id?: string;
  created_at: string;
  updated_at: string;
}

/** One-time reveal after checkout (cleared after fetch or expiry). */
export interface KeyReveal {
  session_id: string;
  customer_id: string;
  api_key: string;
  email: string;
  plan_id: PlanId;
  expires_at: string;
}

function customersPath(): string {
  return path.join(dataDirPath(), "customers.json");
}

function revealsPath(): string {
  return path.join(dataDirPath(), "key-reveals.json");
}

function ensure(): void {
  fs.mkdirSync(dataDirPath(), { recursive: true });
}

export function hashApiKey(key: string): string {
  return createHash("sha256").update(key).digest("hex");
}

export function generateApiKey(): string {
  return `af_live_${randomBytes(24).toString("hex")}`;
}

function readCustomers(): Customer[] {
  ensure();
  const p = customersPath();
  if (!fs.existsSync(p)) return [];
  try {
    return JSON.parse(fs.readFileSync(p, "utf8")) as Customer[];
  } catch {
    return [];
  }
}

function writeCustomers(all: Customer[]): void {
  ensure();
  fs.writeFileSync(customersPath(), JSON.stringify(all, null, 2));
}

function readReveals(): KeyReveal[] {
  ensure();
  const p = revealsPath();
  if (!fs.existsSync(p)) return [];
  try {
    return JSON.parse(fs.readFileSync(p, "utf8")) as KeyReveal[];
  } catch {
    return [];
  }
}

function writeReveals(all: KeyReveal[]): void {
  ensure();
  fs.writeFileSync(revealsPath(), JSON.stringify(all, null, 2));
}

export function listCustomers(): Customer[] {
  return readCustomers();
}

export function findCustomerByKey(apiKey: string): Customer | undefined {
  const hash = hashApiKey(apiKey);
  return readCustomers().find((c) => c.api_key_hash === hash);
}

export function findCustomerByEmail(email: string): Customer | undefined {
  const e = email.trim().toLowerCase();
  return readCustomers().find((c) => c.email === e);
}

export function findCustomerById(id: string): Customer | undefined {
  return readCustomers().find((c) => c.id === id);
}

export function findCustomerByStripeCustomer(stripeCustomerId: string): Customer | undefined {
  return readCustomers().find((c) => c.stripe_customer_id === stripeCustomerId);
}

export function upsertCustomer(customer: Customer): Customer {
  const all = readCustomers();
  const idx = all.findIndex((c) => c.id === customer.id);
  if (idx >= 0) all[idx] = customer;
  else all.unshift(customer);
  writeCustomers(all);
  return customer;
}

export function issueCustomer(opts: {
  email: string;
  name?: string;
  plan_id: PlanId;
  tier: Tier;
  status?: Customer["status"];
  stripe_customer_id?: string;
  stripe_subscription_id?: string;
  existing?: Customer;
}): { customer: Customer; api_key: string } {
  const api_key = generateApiKey();
  const now = new Date().toISOString();
  const base = opts.existing;
  const customer: Customer = {
    id: base?.id ?? `cus_${randomBytes(8).toString("hex")}`,
    email: opts.email.trim().toLowerCase(),
    name: opts.name?.trim() || base?.name,
    plan_id: opts.plan_id,
    tier: opts.tier,
    status: opts.status ?? "active",
    api_key_hash: hashApiKey(api_key),
    api_key_prefix: `${api_key.slice(0, 12)}…`,
    stripe_customer_id: opts.stripe_customer_id ?? base?.stripe_customer_id,
    stripe_subscription_id: opts.stripe_subscription_id ?? base?.stripe_subscription_id,
    created_at: base?.created_at ?? now,
    updated_at: now,
  };
  upsertCustomer(customer);
  return { customer, api_key };
}

export function saveKeyReveal(reveal: KeyReveal): void {
  const all = readReveals().filter(
    (r) => r.session_id !== reveal.session_id && new Date(r.expires_at).getTime() > Date.now(),
  );
  all.push(reveal);
  writeReveals(all);
}

export function consumeKeyReveal(sessionId: string): KeyReveal | undefined {
  const all = readReveals();
  const idx = all.findIndex((r) => r.session_id === sessionId);
  if (idx < 0) return undefined;
  const hit = all[idx]!;
  if (new Date(hit.expires_at).getTime() < Date.now()) {
    all.splice(idx, 1);
    writeReveals(all);
    return undefined;
  }
  all.splice(idx, 1);
  writeReveals(all);
  return hit;
}

export function updateCustomerBilling(
  customerId: string,
  patch: Partial<
    Pick<
      Customer,
      | "plan_id"
      | "tier"
      | "status"
      | "stripe_customer_id"
      | "stripe_subscription_id"
      | "name"
    >
  >,
): Customer | undefined {
  const all = readCustomers();
  const idx = all.findIndex((c) => c.id === customerId);
  if (idx < 0) return undefined;
  const next: Customer = {
    ...all[idx]!,
    ...patch,
    updated_at: new Date().toISOString(),
  };
  all[idx] = next;
  writeCustomers(all);
  return next;
}
export function bumpCustomerUsage(customerId: string): number {
  ensure();
  const day = new Date().toISOString().slice(0, 10);
  const p = path.join(dataDirPath(), "usage-by-customer.json");
  let all: Record<string, { day: string; evaluations: number }> = {};
  try {
    if (fs.existsSync(p)) all = JSON.parse(fs.readFileSync(p, "utf8"));
  } catch {
    all = {};
  }
  const cur = all[customerId];
  const next = !cur || cur.day !== day ? { day, evaluations: 1 } : { day, evaluations: cur.evaluations + 1 };
  all[customerId] = next;
  fs.writeFileSync(p, JSON.stringify(all, null, 2));
  return next.evaluations;
}

export function getCustomerUsage(customerId: string): { day: string; evaluations: number } {
  const day = new Date().toISOString().slice(0, 10);
  const p = path.join(dataDirPath(), "usage-by-customer.json");
  try {
    if (fs.existsSync(p)) {
      const all = JSON.parse(fs.readFileSync(p, "utf8")) as Record<
        string,
        { day: string; evaluations: number }
      >;
      const cur = all[customerId];
      if (cur?.day === day) return cur;
    }
  } catch {
    /* ignore */
  }
  return { day, evaluations: 0 };
}
