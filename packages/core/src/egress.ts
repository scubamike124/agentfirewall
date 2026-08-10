import type { Finding } from "./types.js";

export type EgressMode = "off" | "observe" | "enforce";

/**
 * Match destination against allowlist entries.
 * Entries may be exact hosts, `*.example.com`, URL prefixes, or `/regex/`.
 */
export function destinationAllowed(destination: string, allowlist: string[]): boolean {
  if (!allowlist.length) return false;
  const dest = destination.trim();
  let host = dest;
  try {
    const u = new URL(dest.includes("://") ? dest : `https://${dest}`);
    host = u.hostname;
  } catch {
    /* use raw */
  }

  for (const entry of allowlist) {
    const e = entry.trim();
    if (!e) continue;
    if (e === "*") return true;
    if (e.startsWith("/") && e.lastIndexOf("/") > 0) {
      const last = e.lastIndexOf("/");
      try {
        if (new RegExp(e.slice(1, last), e.slice(last + 1) || "i").test(dest)) return true;
      } catch {
        /* skip bad regex */
      }
      continue;
    }
    if (e.startsWith("*.")) {
      const suffix = e.slice(1); // .example.com
      if (host === e.slice(2) || host.endsWith(suffix)) return true;
      continue;
    }
    if (dest === e || dest.startsWith(e) || host === e || host.endsWith(`.${e}`)) return true;
  }
  return false;
}

export function inspectEgress(opts: {
  destination?: string;
  allowlist?: string[];
  mode: EgressMode;
}): Finding[] {
  const { destination, allowlist, mode } = opts;
  if (mode === "off" || !destination) return [];

  const list = allowlist ?? [];
  if (!list.length) {
    if (mode === "enforce") {
      return [
        {
          detector: "egress",
          severity: "critical",
          code: "egress.no_allowlist",
          message: "Egress enforce mode requires a destination allowlist for this agent",
          evidence: destination.slice(0, 160),
        },
      ];
    }
    return [
      {
        detector: "egress",
        severity: "medium",
        code: "egress.unconfigured",
        message: "Destination present but agent has no egress allowlist",
        evidence: destination.slice(0, 160),
      },
    ];
  }

  if (!destinationAllowed(destination, list)) {
    return [
      {
        detector: "egress",
        severity: "critical",
        code: "egress.not_allowlisted",
        message: "Destination is not on the agent egress allowlist",
        evidence: destination.slice(0, 160),
      },
    ];
  }
  return [];
}
