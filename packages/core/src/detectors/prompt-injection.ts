import type { Finding } from "../types.js";

const INJECTION_PATTERNS: Array<{ code: string; re: RegExp; message: string; severity: Finding["severity"] }> = [
  {
    code: "injection.ignore_instructions",
    re: /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|rules|prompts)/i,
    message: "Content attempts to override prior system instructions",
    severity: "critical",
  },
  {
    code: "injection.system_prompt_leak",
    re: /(?:reveal|print|show|dump)\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions)/i,
    message: "Content attempts to extract system prompt",
    severity: "high",
  },
  {
    code: "injection.exfiltrate",
    re: /(?:send|exfiltrate|upload|post)\s+(?:all\s+)?(?:secrets|api\s*keys|credentials|passwords)\s+to/i,
    message: "Content instructs secret exfiltration",
    severity: "critical",
  },
  {
    code: "injection.role_hijack",
    re: /(?:you\s+are\s+now|act\s+as|pretend\s+to\s+be)\s+(?:a\s+)?(?:unrestricted|jailbroken|DAN|root)/i,
    message: "Role-hijack / jailbreak language",
    severity: "high",
  },
  {
    code: "injection.disable_safety",
    re: /(?:disable|bypass|turn\s+off)\s+(?:all\s+)?(?:safety|security|guardrails|policies|filters)/i,
    message: "Attempt to disable safety controls",
    severity: "critical",
  },
  {
    code: "injection.tool_poison",
    re: /(?:when\s+(?:this\s+)?tool\s+is\s+used|before\s+calling|hidden\s+instruction).{0,80}(?:ignore|exfiltrate|send\s+to)/is,
    message: "Possible tool-description poisoning",
    severity: "high",
  },
  {
    code: "injection.mcp_override",
    re: /mcp[:\s].{0,40}(?:ignore\s+policy|grant\s+admin|full\s+access)/i,
    message: "MCP description requests policy override",
    severity: "high",
  },
  {
    code: "injection.sudo_mode",
    re: /\b(?:sudo\s+mode|developer\s+mode\s+enabled|do\s+anything\s+now)\b/i,
    message: "Classic jailbreak cue",
    severity: "medium",
  },
];

export function detectPromptInjection(texts: string[]): Finding[] {
  const findings: Finding[] = [];
  const joined = texts.filter(Boolean).join("\n---\n");
  if (!joined.trim()) return findings;

  for (const p of INJECTION_PATTERNS) {
    if (p.re.test(joined)) {
      findings.push({
        detector: "prompt_injection",
        severity: p.severity,
        code: p.code,
        message: p.message,
      });
    }
  }
  return findings;
}
