import { randomBytes, createHash } from "crypto";
import fs from "fs";
import path from "path";
import type { AgentIdentity } from "./types.js";

export interface IssuedCredential {
  agent_id: string;
  credential_id: string;
  /** Short-lived bearer token — treat as secret. Only present at issue time. */
  token?: string;
  scopes: string[];
  expires_at: string;
  org_id?: string;
}

interface StoredCred {
  agent_id: string;
  credential_id: string;
  token_hash: string;
  scopes: string[];
  expires_at: string;
  org_id?: string;
}

export interface AgentRegistryEntry {
  agent_id: string;
  display_name?: string;
  scopes: string[];
  org_id?: string;
  egress_allowlist?: string[];
  created_at: string;
  last_seen_at?: string;
}

/** Persistable agent identity + short-lived credentials (hashed at rest). */
export class AgentCredentialStore {
  private byToken = new Map<string, StoredCred>();
  private byAgent = new Map<string, string[]>();
  private agents = new Map<string, AgentRegistryEntry>();
  private persistPath: string | null;

  constructor(persistPath?: string | null) {
    this.persistPath = persistPath ?? null;
    this.load();
  }

  private load(): void {
    if (!this.persistPath) return;
    try {
      if (!fs.existsSync(this.persistPath)) return;
      const raw = JSON.parse(fs.readFileSync(this.persistPath, "utf8")) as {
        credentials?: StoredCred[];
        agents?: AgentRegistryEntry[];
      };
      for (const c of raw.credentials ?? []) {
        if (new Date(c.expires_at).getTime() < Date.now()) continue;
        this.byToken.set(c.token_hash, c);
        const list = this.byAgent.get(c.agent_id) ?? [];
        list.push(c.token_hash);
        this.byAgent.set(c.agent_id, list);
      }
      for (const a of raw.agents ?? []) this.agents.set(a.agent_id, a);
    } catch {
      /* ignore corrupt */
    }
  }

  private save(): void {
    if (!this.persistPath) return;
    try {
      fs.mkdirSync(path.dirname(this.persistPath), { recursive: true });
      const credentials = [...this.byToken.values()];
      const agents = [...this.agents.values()];
      const tmp = `${this.persistPath}.${process.pid}.tmp`;
      fs.writeFileSync(tmp, JSON.stringify({ credentials, agents }, null, 2), { mode: 0o600 });
      fs.renameSync(tmp, this.persistPath);
    } catch {
      /* best-effort */
    }
  }

  upsertAgent(agent: AgentIdentity): AgentRegistryEntry {
    const existing = this.agents.get(agent.agent_id);
    const entry: AgentRegistryEntry = {
      agent_id: agent.agent_id,
      display_name: agent.display_name ?? existing?.display_name,
      scopes: agent.scopes?.length ? [...agent.scopes] : existing?.scopes ?? ["tools:default"],
      org_id: agent.org_id ?? existing?.org_id,
      egress_allowlist:
        agent.egress_allowlist !== undefined
          ? [...agent.egress_allowlist]
          : existing?.egress_allowlist,
      created_at: existing?.created_at ?? new Date().toISOString(),
      last_seen_at: new Date().toISOString(),
    };
    this.agents.set(agent.agent_id, entry);
    this.save();
    return entry;
  }

  setEgressAllowlist(agentId: string, allowlist: string[]): AgentRegistryEntry | null {
    const existing = this.agents.get(agentId);
    if (!existing) return null;
    existing.egress_allowlist = [...allowlist];
    existing.last_seen_at = new Date().toISOString();
    this.agents.set(agentId, existing);
    this.save();
    return existing;
  }

  getAgent(agentId: string): AgentRegistryEntry | undefined {
    return this.agents.get(agentId);
  }

  listAgents(): AgentRegistryEntry[] {
    return [...this.agents.values()];
  }

  issue(agent: AgentIdentity, ttlSeconds = 3600): IssuedCredential {
    this.upsertAgent(agent);
    const credential_id = `cred_${randomBytes(8).toString("hex")}`;
    const token = `af_${randomBytes(24).toString("base64url")}`;
    const token_hash = createHash("sha256").update(token).digest("hex");
    const expires_at = new Date(Date.now() + ttlSeconds * 1000).toISOString();
    const scopes = agent.scopes?.length
      ? [...agent.scopes]
      : this.agents.get(agent.agent_id)?.scopes ?? ["tools:default"];
    const record: StoredCred = {
      agent_id: agent.agent_id,
      credential_id,
      token_hash,
      scopes,
      expires_at,
      org_id: agent.org_id,
    };
    this.byToken.set(token_hash, record);
    const list = this.byAgent.get(agent.agent_id) ?? [];
    list.push(token_hash);
    this.byAgent.set(agent.agent_id, list);
    this.save();
    return {
      agent_id: agent.agent_id,
      credential_id,
      token,
      scopes,
      expires_at,
      org_id: agent.org_id,
    };
  }

  verify(token: string): IssuedCredential | null {
    const token_hash = createHash("sha256").update(token).digest("hex");
    const rec = this.byToken.get(token_hash);
    if (!rec) return null;
    if (new Date(rec.expires_at).getTime() < Date.now()) {
      this.byToken.delete(token_hash);
      this.save();
      return null;
    }
    const agent = this.agents.get(rec.agent_id);
    if (agent) {
      agent.last_seen_at = new Date().toISOString();
      this.save();
    }
    return {
      agent_id: rec.agent_id,
      credential_id: rec.credential_id,
      scopes: rec.scopes,
      expires_at: rec.expires_at,
      org_id: rec.org_id,
    };
  }

  /** True if agent scopes allow the tool (tools:default = all non-admin; tools:* = all). */
  scopeAllows(scopes: string[], tool: string): boolean {
    if (scopes.includes("tools:*") || scopes.includes("*")) return true;
    if (scopes.includes(`tool:${tool}`)) return true;
    if (scopes.includes("tools:default") && !/admin|iam|root/i.test(tool)) return true;
    return scopes.some((s) => s.startsWith("tools:") && tool.startsWith(s.slice(6)));
  }

  revokeAgent(agentId: string): void {
    const hashes = this.byAgent.get(agentId) ?? [];
    for (const h of hashes) this.byToken.delete(h);
    this.byAgent.delete(agentId);
    this.save();
  }
}
