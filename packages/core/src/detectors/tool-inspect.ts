import type { Finding, ProposedAction } from "../types.js";

const HIGH_RISK_TOOLS = new Set([
  "shell",
  "bash",
  "exec",
  "run_command",
  "file_write",
  "write_file",
  "delete_file",
  "http_request",
  "fetch",
  "browser",
  "send_email",
  "transfer_funds",
  "payment",
  "db_execute",
  "sql_exec",
]);

const DESTRUCTIVE_PARAM_KEYS = /^(sql|command|cmd|script|code|body|url|path|to|recipient)$/i;

export function inspectToolCall(action: ProposedAction, destination?: string): Finding[] {
  const findings: Finding[] = [];
  const tool = (action.tool || "").toLowerCase();
  const type = (action.type || "").toLowerCase();
  const dest = (destination || action.destination || "").toLowerCase();

  if (HIGH_RISK_TOOLS.has(tool) || /shell|exec|payment|transfer|delete/i.test(tool)) {
    findings.push({
      detector: "tool_inspect",
      severity: /payment|transfer|shell|exec|delete/i.test(tool) ? "high" : "medium",
      code: "tool.high_risk",
      message: `Tool "${action.tool}" is classified as elevated risk`,
    });
  }

  if (type === "mcp_call" || tool.startsWith("mcp.")) {
    findings.push({
      detector: "tool_inspect",
      severity: "medium",
      code: "tool.mcp_call",
      message: "MCP tool invocation — verify server trust and description integrity",
    });
  }

  if (dest) {
    if (/localhost|127\.0\.0\.1|0\.0\.0\.0|metadata\.google|169\.169\.|169\.254\./i.test(dest)) {
      findings.push({
        detector: "tool_inspect",
        severity: "critical",
        code: "tool.ssrf_local",
        message: "Destination targets local/metadata network — possible SSRF",
        evidence: dest.slice(0, 120),
      });
    }
    if (/pastebin|webhook\.site|ngrok|requestbin|burpcollaborator/i.test(dest)) {
      findings.push({
        detector: "tool_inspect",
        severity: "high",
        code: "tool.exfil_destination",
        message: "Destination resembles a known exfiltration / callback sink",
        evidence: dest.slice(0, 120),
      });
    }
  }

  if (typeof action.amount === "number" && action.amount >= 1000) {
    findings.push({
      detector: "tool_inspect",
      severity: action.amount >= 10000 ? "critical" : "high",
      code: "tool.high_amount",
      message: `High-value amount ${action.amount}${action.currency ? ` ${action.currency}` : ""}`,
    });
  }

  const params = action.parameters ?? {};
  for (const [k, v] of Object.entries(params)) {
    if (DESTRUCTIVE_PARAM_KEYS.test(k) && typeof v === "string") {
      if (/drop\s+table|rm\s+-rf|curl\s+[^\n]+\$\(|wget\s+/i.test(v)) {
        findings.push({
          detector: "tool_inspect",
          severity: "critical",
          code: "tool.destructive_payload",
          message: `Parameter "${k}" contains destructive or download-exec content`,
        });
      }
    }
  }

  return findings;
}
