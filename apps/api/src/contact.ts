/**
 * Public contact form → Resend → private inbox (never expose personal email in UI).
 */
import fs from "fs";
import path from "path";
import { dataDirPath } from "./store.js";

export interface ContactPayload {
  name: string;
  email: string;
  company?: string;
  message: string;
  /** Honeypot — bots fill this; humans leave empty */
  website?: string;
}

const rateWindowMs = 15 * 60 * 1000;
const rateMax = 5;
const hits = new Map<string, number[]>();

function rateOk(ip: string): boolean {
  const now = Date.now();
  const list = (hits.get(ip) ?? []).filter((t) => now - t < rateWindowMs);
  if (list.length >= rateMax) {
    hits.set(ip, list);
    return false;
  }
  list.push(now);
  hits.set(ip, list);
  return true;
}

function appendContactLog(entry: Record<string, unknown>): void {
  try {
    fs.mkdirSync(dataDirPath(), { recursive: true });
    fs.appendFileSync(
      path.join(dataDirPath(), "contact.jsonl"),
      `${JSON.stringify({ ...entry, at: new Date().toISOString() })}\n`,
    );
  } catch {
    /* best-effort */
  }
}

export async function sendContactEmail(
  payload: ContactPayload,
  opts: { ip?: string },
): Promise<{ ok: true } | { ok: false; error: string; status: number }> {
  if (payload.website?.trim()) {
    // Silent success for honeypot
    return { ok: true };
  }
  const name = payload.name?.trim().slice(0, 120);
  const email = payload.email?.trim().slice(0, 200);
  const message = payload.message?.trim().slice(0, 5000);
  const company = payload.company?.trim().slice(0, 200) || "";

  if (!name || !email || !message) {
    return { ok: false, error: "name, email, and message are required", status: 400 };
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return { ok: false, error: "invalid email", status: 400 };
  }
  if (message.length < 10) {
    return { ok: false, error: "message too short", status: 400 };
  }

  const ip = opts.ip || "unknown";
  if (!rateOk(ip)) {
    return { ok: false, error: "Too many messages — try again later", status: 429 };
  }

  const apiKey = process.env.RESEND_API_KEY;
  const to = process.env.AGENTFIREWALL_CONTACT_TO || process.env.CONTACT_TO_EMAIL;
  const from =
    process.env.AGENTFIREWALL_MAIL_FROM ||
    process.env.MAIL_FROM ||
    "AgentFirewall <onboarding@resend.dev>";

  if (!apiKey?.startsWith("re_")) {
    return { ok: false, error: "Contact email is not configured (RESEND_API_KEY)", status: 503 };
  }
  if (!to?.includes("@")) {
    return {
      ok: false,
      error: "Contact inbox not configured (AGENTFIREWALL_CONTACT_TO)",
      status: 503,
    };
  }

  const subject = `[AgentFirewall] Contact from ${name}${company ? ` (${company})` : ""}`;
  const text = [
    `Name: ${name}`,
    `Email: ${email}`,
    company ? `Company: ${company}` : null,
    `IP: ${ip}`,
    "",
    message,
  ]
    .filter(Boolean)
    .join("\n");

  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({
      from,
      to: [to],
      reply_to: email,
      subject,
      text,
    }),
  });

  const body = (await res.json().catch(() => ({}))) as { id?: string; message?: string };
  if (!res.ok) {
    appendContactLog({ ok: false, email, error: body.message || res.status });
    return {
      ok: false,
      error: body.message || `Resend error ${res.status}`,
      status: 502,
    };
  }

  appendContactLog({ ok: true, email, name, resend_id: body.id });
  return { ok: true };
}

export function contactConfigured(): {
  resend: boolean;
  inbox: boolean;
  from: string;
} {
  return {
    resend: Boolean(process.env.RESEND_API_KEY?.startsWith("re_")),
    inbox: Boolean(
      (process.env.AGENTFIREWALL_CONTACT_TO || process.env.CONTACT_TO_EMAIL)?.includes("@"),
    ),
    from: process.env.AGENTFIREWALL_MAIL_FROM || process.env.MAIL_FROM || "AgentFirewall <onboarding@resend.dev>",
  };
}

/** Transactional email to a customer (API key delivery, etc.). */
export async function sendCustomerEmail(opts: {
  to: string;
  subject: string;
  text: string;
}): Promise<{ ok: true } | { ok: false; error: string }> {
  const apiKey = process.env.RESEND_API_KEY;
  const from =
    process.env.AGENTFIREWALL_MAIL_FROM ||
    process.env.MAIL_FROM ||
    "AgentFirewall <onboarding@resend.dev>";
  if (!apiKey?.startsWith("re_")) {
    return { ok: false, error: "RESEND_API_KEY not configured" };
  }
  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({
      from,
      to: [opts.to],
      subject: opts.subject,
      text: opts.text,
    }),
  });
  const body = (await res.json().catch(() => ({}))) as { message?: string };
  if (!res.ok) return { ok: false, error: body.message || `Resend ${res.status}` };
  return { ok: true };
}
