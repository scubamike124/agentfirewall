import type { Finding } from "../types.js";
import { detectPromptInjection } from "./prompt-injection.js";

/**
 * Inspect MCP server/tool descriptors for poisoning before an agent trusts them.
 */
export function inspectMcpDescriptors(
  descriptors: Array<{ name?: string; description?: string; server?: string } | string>,
): Finding[] {
  const texts: string[] = [];
  for (const d of descriptors) {
    if (typeof d === "string") texts.push(d);
    else texts.push([d.server, d.name, d.description].filter(Boolean).join("\n"));
  }
  const findings = detectPromptInjection(texts).map((f) => ({
    ...f,
    detector: "mcp_poisoning",
    code: f.code.replace(/^injection\./, "mcp."),
  }));

  for (const t of texts) {
    if (/always\s+call\s+this\s+tool\s+first|required\s+side[\s-]?effect/i.test(t)) {
      findings.push({
        detector: "mcp_poisoning",
        severity: "high",
        code: "mcp.forced_invocation",
        message: "MCP description attempts to force tool invocation",
      });
    }
    if (/exfiltrat|send\s+(api\s*)?keys|upload\s+credentials/i.test(t)) {
      findings.push({
        detector: "mcp_poisoning",
        severity: "critical",
        code: "mcp.exfil_instruction",
        message: "MCP description instructs credential exfiltration",
      });
    }
  }
  return findings;
}
