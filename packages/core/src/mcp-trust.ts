import { createHash } from "crypto";
import type { Finding } from "./types.js";

export interface McpToolPin {
  name: string;
  description_hash: string;
  description?: string;
}

export interface McpServerTrust {
  server: string;
  /** observe = alert first-seen/drift; pin = block unknown/changed */
  mode: "observe" | "pin";
  tools: McpToolPin[];
}

export interface McpTrustRegistry {
  servers: McpServerTrust[];
}

export function hashDescriptor(text: string): string {
  return createHash("sha256").update(text.trim()).digest("hex");
}

export type McpDescriptorInput =
  | string
  | { server?: string; name?: string; description?: string };

function normalize(d: McpDescriptorInput): { server: string; name: string; description: string; hash: string } {
  if (typeof d === "string") {
    return {
      server: "default",
      name: "unnamed",
      description: d,
      hash: hashDescriptor(d),
    };
  }
  const description = d.description ?? "";
  const name = d.name ?? "unnamed";
  const server = d.server ?? "default";
  return {
    server,
    name,
    description,
    hash: hashDescriptor(`${server}\n${name}\n${description}`),
  };
}

/**
 * Supply-chain checks for MCP descriptors: first-seen, drift, unpinned servers.
 * Mutates registry when observe/pin learns a first-seen tool (caller should persist).
 */
export function inspectMcpTrust(
  descriptors: McpDescriptorInput[],
  registry: McpTrustRegistry,
  opts?: { learn?: boolean },
): { findings: Finding[]; registry: McpTrustRegistry; changed: boolean } {
  const findings: Finding[] = [];
  let changed = false;
  const servers = structuredClone(registry.servers ?? []);

  for (const raw of descriptors) {
    const d = normalize(raw);
    let entry = servers.find((s) => s.server === d.server);
    if (!entry) {
      findings.push({
        detector: "mcp_trust",
        severity: "high",
        code: "mcp.untrusted_server",
        message: `MCP server "${d.server}" is not in the trust registry`,
        evidence: d.name,
      });
      if (opts?.learn !== false) {
        entry = { server: d.server, mode: "observe", tools: [] };
        servers.push(entry);
        changed = true;
        findings.push({
          detector: "mcp_trust",
          severity: "medium",
          code: "mcp.first_seen",
          message: `First-seen MCP server "${d.server}" — recorded in observe mode`,
        });
      } else {
        continue;
      }
    }

    const pinned = entry.tools.find((t) => t.name === d.name);
    if (!pinned) {
      const pinBlock = entry.mode === "pin";
      findings.push({
        detector: "mcp_trust",
        severity: pinBlock ? "critical" : "medium",
        code: pinBlock ? "mcp.pin_violation" : "mcp.first_seen",
        message: `First-seen MCP tool "${d.name}" on server "${d.server}"`,
      });
      if (opts?.learn !== false && !pinBlock) {
        entry.tools.push({
          name: d.name,
          description_hash: d.hash,
          description: d.description.slice(0, 500),
        });
        changed = true;
      }
      continue;
    }

    if (pinned.description_hash !== d.hash) {
      const pinBlock = entry.mode === "pin";
      findings.push({
        detector: "mcp_trust",
        severity: pinBlock ? "critical" : "high",
        code: pinBlock ? "mcp.pin_violation" : "mcp.descriptor_drift",
        message: `MCP tool "${d.name}" description changed since last trusted hash`,
        evidence: `${pinned.description_hash.slice(0, 12)}→${d.hash.slice(0, 12)}`,
      });
    }
  }

  return { findings, registry: { servers }, changed };
}
