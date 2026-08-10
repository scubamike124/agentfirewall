/** Product tier configuration — same core, gated enterprise surfaces. */

export type Tier = "developer" | "pro" | "business" | "enterprise";

export interface TierLimits {
  evaluations_per_day: number;
  audit_retention_days: number;
  max_agents: number;
  custom_policies: boolean;
  siem_export: boolean;
  sso: boolean;
  rbac: boolean;
  private_networking: boolean;
  compliance_export: boolean;
}

export const TIER_LIMITS: Record<Tier, TierLimits> = {
  developer: {
    evaluations_per_day: 5_000,
    audit_retention_days: 7,
    max_agents: 5,
    custom_policies: true,
    siem_export: false,
    sso: false,
    rbac: false,
    private_networking: false,
    compliance_export: false,
  },
  pro: {
    evaluations_per_day: 50_000,
    audit_retention_days: 30,
    max_agents: 25,
    custom_policies: true,
    siem_export: true,
    sso: false,
    rbac: false,
    private_networking: false,
    compliance_export: true,
  },
  business: {
    evaluations_per_day: 250_000,
    audit_retention_days: 90,
    max_agents: 100,
    custom_policies: true,
    siem_export: true,
    sso: true,
    rbac: true,
    private_networking: false,
    compliance_export: true,
  },
  enterprise: {
    evaluations_per_day: Number.MAX_SAFE_INTEGER,
    audit_retention_days: 365,
    max_agents: Number.MAX_SAFE_INTEGER,
    custom_policies: true,
    siem_export: true,
    sso: true,
    rbac: true,
    private_networking: true,
    compliance_export: true,
  },
};

export function resolveTier(envTier?: string): Tier {
  const t = (envTier ?? process.env.AGENTFIREWALL_TIER ?? "developer").toLowerCase();
  if (t === "pro" || t === "business" || t === "enterprise") return t;
  return "developer";
}
