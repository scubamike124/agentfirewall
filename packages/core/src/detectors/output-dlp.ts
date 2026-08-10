import type { Decision, Finding, RiskLevel } from "../types.js";
import { detectSecrets, redactDeep } from "./secrets.js";
import { scoreFindings, riskLevelFromScore } from "../policy.js";

export interface OutputInspectResult {
  decision: Decision;
  risk_score: number;
  risk_level: RiskLevel;
  findings: Finding[];
  result_redacted: unknown;
  explanation: string;
}

/** Scan tool/API results before they return to the model or next tool. */
export function inspectToolOutput(result: unknown, opts?: { tool?: string }): OutputInspectResult {
  const findings = detectSecrets([result]).map((f) => ({
    ...f,
    detector: "output_dlp",
    code: f.code.replace(/^secret\./, "output."),
    message: `Tool output: ${f.message}`,
  }));

  if (opts?.tool && /http|fetch|browser|shell|file_read/i.test(opts.tool)) {
    const text = typeof result === "string" ? result : JSON.stringify(result ?? "");
    if (/-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/.test(text)) {
      findings.push({
        detector: "output_dlp",
        severity: "critical",
        code: "output.private_key",
        message: "Tool output contains a private key block",
      });
    }
  }

  const risk_score = scoreFindings(findings);
  const risk_level = riskLevelFromScore(risk_score);
  const critical = findings.some((f) => f.severity === "critical" || f.severity === "high");
  const decision: Decision = critical ? "block" : findings.length ? "approval_required" : "allow";

  return {
    decision,
    risk_score,
    risk_level,
    findings,
    result_redacted: redactDeep(result),
    explanation:
      decision === "allow"
        ? "Tool output passed DLP checks"
        : `Output DLP ${decision}: ${findings.map((f) => f.message).slice(0, 2).join("; ")}`,
  };
}
