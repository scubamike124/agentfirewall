import type { Finding } from "../types.js";

const SECRET_PATTERNS: Array<{ code: string; re: RegExp; message: string; severity: Finding["severity"] }> = [
  {
    code: "secret.aws_access_key",
    re: /\bAKIA[0-9A-Z]{16}\b/g,
    message: "Possible AWS access key id",
    severity: "critical",
  },
  {
    code: "secret.aws_secret",
    re: /\b(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])\b/g,
    message: "Possible AWS secret access key shaped token",
    severity: "critical",
  },
  {
    code: "secret.github_pat",
    re: /\bghp_[A-Za-z0-9]{36,}\b/g,
    message: "GitHub personal access token",
    severity: "critical",
  },
  {
    code: "secret.github_fine",
    re: /\bgithub_pat_[A-Za-z0-9_]{20,}\b/g,
    message: "GitHub fine-grained PAT",
    severity: "critical",
  },
  {
    code: "secret.openai",
    re: /\bsk-[A-Za-z0-9]{20,}\b/g,
    message: "OpenAI-style API key",
    severity: "critical",
  },
  {
    code: "secret.anthropic",
    re: /\bsk-ant-[A-Za-z0-9\-_]{20,}\b/g,
    message: "Anthropic-style API key",
    severity: "critical",
  },
  {
    code: "secret.stripe",
    re: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b/g,
    message: "Stripe secret key",
    severity: "critical",
  },
  {
    code: "secret.slack",
    re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g,
    message: "Slack token",
    severity: "critical",
  },
  {
    code: "secret.jwt",
    re: /\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g,
    message: "JWT-like bearer token",
    severity: "high",
  },
  {
    code: "secret.private_key",
    re: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g,
    message: "PEM private key material",
    severity: "critical",
  },
  {
    code: "secret.password_assignment",
    re: /\b(?:password|passwd|pwd|secret|api[_-]?key|token)\s*[=:]\s*['"][^'"]{8,}['"]/gi,
    message: "Password or secret assignment in plaintext",
    severity: "critical",
  },
  {
    code: "secret.ssn",
    re: /\b\d{3}-\d{2}-\d{4}\b/g,
    message: "Possible US SSN",
    severity: "high",
  },
  {
    code: "secret.email_bulk",
    re: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi,
    message: "Email address in outbound payload",
    severity: "high",
  },
];

/** Zero-width / soft-hyphen / BOM / word-joiner and similar obfuscators. */
const INVISIBLE_RE = /[\u200B-\u200D\uFEFF\u2060\u00AD\u180E\u2061-\u2064]/g;

/** Map common fullwidth ASCII lookalikes used in obfuscation. */
const FULLWIDTH_OFFSET = 0xff00 - 0x20;

function collectText(value: unknown, out: string[]): void {
  if (value == null) return;
  if (typeof value === "string") {
    out.push(value);
    return;
  }
  if (typeof value === "number" || typeof value === "boolean") return;
  if (Array.isArray(value)) {
    for (const v of value) collectText(v, out);
    return;
  }
  if (typeof value === "object") {
    for (const v of Object.values(value as Record<string, unknown>)) collectText(v, out);
  }
}

function stripInvisible(s: string): string {
  return s.replace(INVISIBLE_RE, "");
}

function foldFullwidth(s: string): string {
  let out = "";
  for (const ch of s) {
    const cp = ch.codePointAt(0)!;
    if (cp >= 0xff01 && cp <= 0xff5e) {
      out += String.fromCodePoint(cp - FULLWIDTH_OFFSET);
    } else {
      out += ch;
    }
  }
  return out;
}

function normalizeObfuscation(s: string): string {
  return foldFullwidth(stripInvisible(s));
}

function isMostlyPrintable(s: string): boolean {
  if (!s || s.length < 4) return false;
  let ok = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 9 || c === 10 || c === 13 || (c >= 32 && c < 127) || c >= 160) ok += 1;
  }
  return ok / s.length >= 0.85;
}

function tryUrlDecode(s: string): string | null {
  if (!/%[0-9A-Fa-f]{2}/.test(s)) return null;
  try {
    const once = decodeURIComponent(s.replace(/\+/g, " "));
    if (once === s) return null;
    // Support light double-encoding without looping forever.
    if (/%[0-9A-Fa-f]{2}/.test(once)) {
      try {
        const twice = decodeURIComponent(once.replace(/\+/g, " "));
        if (twice !== once) return twice;
      } catch {
        /* keep once */
      }
    }
    return once;
  } catch {
    return null;
  }
}

function tryBase64Decodes(s: string): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const candidates = new Set<string>();
  const compact = s.replace(/\s+/g, "");
  if (/^[A-Za-z0-9+/]+=*$/.test(compact) && compact.length >= 20 && compact.length % 4 === 0) {
    candidates.add(compact);
  }
  for (const m of s.match(/[A-Za-z0-9+/]{20,}={0,2}/g) ?? []) {
    if (m.length % 4 === 0 || m.endsWith("=")) candidates.add(m);
  }
  for (const c of candidates) {
    try {
      const buf = Buffer.from(c, "base64");
      if (buf.length < 8) continue;
      const decoded = buf.toString("utf8");
      if (!isMostlyPrintable(decoded) || seen.has(decoded)) continue;
      seen.add(decoded);
      out.push(decoded);
    } catch {
      /* ignore */
    }
  }
  return out;
}

function tryHexDecodes(s: string): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const candidates = new Set<string>();
  const compact = s.replace(/\s+/g, "");
  if (/^[0-9a-fA-F]+$/.test(compact) && compact.length >= 40 && compact.length % 2 === 0) {
    candidates.add(compact);
  }
  for (const m of s.match(/\b(?:0x)?[0-9a-fA-F]{40,}\b/g) ?? []) {
    const hex = m.startsWith("0x") || m.startsWith("0X") ? m.slice(2) : m;
    if (hex.length % 2 === 0) candidates.add(hex);
  }
  for (const c of candidates) {
    try {
      const decoded = Buffer.from(c, "hex").toString("utf8");
      if (!isMostlyPrintable(decoded) || seen.has(decoded)) continue;
      seen.add(decoded);
      out.push(decoded);
    } catch {
      /* ignore */
    }
  }
  return out;
}

/**
 * Build plaintext views of outbound content for secret scanning:
 * raw, normalized (ZW/fullwidth), URL-decoded, base64/hex decoded, and
 * field-concatenated views for fragmented secrets.
 */
export function expandSecretScanTexts(blobs: string[]): string[] {
  const views = new Set<string>();
  const add = (t: string | null | undefined) => {
    if (!t || !t.trim()) return;
    views.add(t);
  };

  const joinedNl = blobs.join("\n");
  const joinedEmpty = blobs.join("");
  add(joinedNl);
  add(joinedEmpty);

  for (const raw of [...blobs, joinedNl, joinedEmpty]) {
    add(raw);
    const norm = normalizeObfuscation(raw);
    add(norm);
    const url = tryUrlDecode(raw) ?? tryUrlDecode(norm);
    if (url) {
      add(url);
      add(normalizeObfuscation(url));
    }
    for (const decoded of [...tryBase64Decodes(raw), ...tryBase64Decodes(norm)]) {
      add(decoded);
      add(normalizeObfuscation(decoded));
      const nestedUrl = tryUrlDecode(decoded);
      if (nestedUrl) add(normalizeObfuscation(nestedUrl));
    }
    for (const decoded of [...tryHexDecodes(raw), ...tryHexDecodes(norm)]) {
      add(decoded);
      add(normalizeObfuscation(decoded));
    }
  }

  return [...views];
}

function scanText(text: string, findings: Finding[], seen: Set<string>): void {
  for (const p of SECRET_PATTERNS) {
    p.re.lastIndex = 0;
    const match = p.re.exec(text);
    if (!match) continue;
    if (p.code === "secret.email_bulk") {
      p.re.lastIndex = 0;
      const all = text.match(p.re) ?? [];
      if (all.length < 3) continue;
    }
    if (p.code === "secret.aws_secret") {
      if (!/aws|secret|akia/i.test(text.slice(Math.max(0, (match.index ?? 0) - 40), (match.index ?? 0) + 80))) {
        continue;
      }
    }
    const key = `${p.code}:${match[0].slice(0, 12)}`;
    if (seen.has(key)) continue;
    seen.add(key);
    findings.push({
      detector: "secrets",
      severity: p.severity,
      code: p.code,
      message: p.message,
      evidence: redact(match[0]),
    });
  }
}

export function detectSecrets(inputs: unknown[]): Finding[] {
  const blobs: string[] = [];
  for (const input of inputs) collectText(input, blobs);
  if (!blobs.length) return [];

  const findings: Finding[] = [];
  const seen = new Set<string>();
  for (const view of expandSecretScanTexts(blobs)) {
    scanText(view, findings, seen);
  }
  return findings;
}

function redact(s: string): string {
  if (s.length <= 8) return "***";
  return `${s.slice(0, 4)}…${s.slice(-4)}`;
}

export function redactDeep(value: unknown): unknown {
  if (typeof value === "string") {
    let out = value;
    for (const p of SECRET_PATTERNS) {
      p.re.lastIndex = 0;
      out = out.replace(p.re, (m) => redact(m));
    }
    // If only an obfuscated/encoded form matches, redact the whole short string.
    if (out === value && detectSecrets([value]).some((f) => f.code.startsWith("secret."))) {
      out = redact(value);
    }
    return out;
  }
  if (Array.isArray(value)) return value.map(redactDeep);
  if (value && typeof value === "object") {
    const o: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (/password|secret|token|api[_-]?key|authorization/i.test(k) && typeof v === "string") {
        o[k] = redact(v);
      } else {
        o[k] = redactDeep(v);
      }
    }
    return o;
  }
  return value;
}
