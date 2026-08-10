import type { Finding, ProposedAction } from "../types.js";

const HIGH_IMPACT =
  /shell|bash|exec|run_command|payment|transfer|http_request|fetch|send_email|delete|admin|iam|db_execute|sql_exec|file_write|write_file/i;

/**
 * Structural gate: untrusted web/tool text must not drive high-impact tools without quarantine.
 * Complements regex injection detectors.
 */
export function inspectUntrustedGate(
  action: ProposedAction,
  untrusted: string[],
): Finding[] {
  const findings: Finding[] = [];
  const texts = untrusted.filter((t) => t?.trim());
  if (!texts.length) return findings;

  findings.push({
    detector: "untrusted_gate",
    severity: "low",
    code: "untrusted.labeled",
    message: "Untrusted content present — treat as data, not instructions",
    evidence: `${texts.length} fragment(s)`,
  });

  const tool = action.tool || "";
  if (HIGH_IMPACT.test(tool) || HIGH_IMPACT.test(action.type || "")) {
    findings.push({
      detector: "untrusted_gate",
      severity: "high",
      code: "untrusted.high_impact_tool",
      message: `High-impact tool "${tool}" invoked while untrusted content is in context`,
    });
  }

  // Structural cue: content that looks like instructions directed at the agent
  const joined = texts.join("\n");
  if (/\b(you must|you should|always|never tell|do not follow|override)\b/i.test(joined)) {
    findings.push({
      detector: "untrusted_gate",
      severity: "medium",
      code: "untrusted.imperative_language",
      message: "Untrusted content contains imperative language aimed at the agent",
    });
  }

  return findings;
}
