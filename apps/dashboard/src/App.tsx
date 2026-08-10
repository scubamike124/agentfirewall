import { useCallback, useEffect, useState } from "react";

type Decision = "allow" | "block" | "approval_required";

type Audit = {
  id: string;
  kind: string;
  agent_id: string;
  tool?: string;
  decision: Decision;
  risk_score: number;
  explanation: string;
  timestamp: string;
  approval_id?: string;
  session_id?: string;
};

type Approval = {
  id: string;
  evaluation_id: string;
  agent_id: string;
  status: "pending" | "approved" | "denied";
  created_at: string;
  action_summary: string;
};

type PolicyRule = {
  id: string;
  name: string;
  enabled: boolean;
  effect: Decision;
};

const defaultKey = "af_dev_key_change_me";

async function api<T>(path: string, key: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    ...init,
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${key}`,
      ...(init?.headers ?? {}),
    },
  });
  if (!res.ok) throw new Error(await res.text());
  return res.json() as Promise<T>;
}

export function App() {
  const [apiKey, setApiKey] = useState(localStorage.getItem("af_key") ?? defaultKey);
  const [base, setBase] = useState(localStorage.getItem("af_base") ?? "");
  const [audit, setAudit] = useState<Audit[]>([]);
  const [approvals, setApprovals] = useState<Approval[]>([]);
  const [rules, setRules] = useState<PolicyRule[]>([]);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const root = base.replace(/\/$/, "") || "";

  const [plans, setPlans] = useState<
    Array<{
      id: string;
      name: string;
      price_usd_month: number;
      description: string;
      features: string[];
      checkout_ready?: boolean;
    }>
  >([]);

  const [contactName, setContactName] = useState("");
  const [contactEmail, setContactEmail] = useState("");
  const [contactCompany, setContactCompany] = useState("");
  const [contactMessage, setContactMessage] = useState("");
  const [contactStatus, setContactStatus] = useState("");
  const [contactBusy, setContactBusy] = useState(false);
  const [contactReady, setContactReady] = useState(false);

  const refresh = useCallback(async () => {
    setBusy(true);
    setError("");
    try {
      localStorage.setItem("af_key", apiKey);
      localStorage.setItem("af_base", base);
      const [a, p, pol, billing, contact] = await Promise.all([
        api<{ events: Audit[] }>(`${root}/v1/audit?limit=50`, apiKey),
        api<{ approvals: Approval[] }>(`${root}/v1/approvals`, apiKey),
        api<{ policy: { rules: PolicyRule[]; default_decision: Decision } }>(
          `${root}/v1/policies`,
          apiKey,
        ),
        fetch(`${root}/v1/billing/plans`).then((r) => r.json()) as Promise<{
          plans: typeof plans;
        }>,
        fetch(`${root}/v1/contact/status`).then((r) => r.json()) as Promise<{ ok: boolean }>,
      ]);
      setAudit(a.events);
      setApprovals(p.approvals.filter((x) => x.status === "pending"));
      setRules(pol.policy.rules);
      setPlans(billing.plans ?? []);
      setContactReady(Boolean(contact.ok));
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }, [apiKey, base, root]);

  useEffect(() => {
    void refresh();
    const t = setInterval(() => void refresh(), 8000);
    return () => clearInterval(t);
  }, [refresh]);

  async function resolve(id: string, status: "approved" | "denied") {
    await api(`${root}/v1/approvals/${id}/resolve`, apiKey, {
      method: "POST",
      body: JSON.stringify({ status }),
    });
    await refresh();
  }

  async function demoEval() {
    await api(`${root}/v1/evaluate`, apiKey, {
      method: "POST",
      body: JSON.stringify({
        agent: { agent_id: "dashboard_demo" },
        action: { type: "tool_call", tool: "shell", parameters: { command: "ls" } },
        context: { session_id: "dashboard_demo_session" },
      }),
    });
    await refresh();
  }

  async function demoTrajectory() {
    const session = `dash_${Date.now()}`;
    await api(`${root}/v1/evaluate`, apiKey, {
      method: "POST",
      body: JSON.stringify({
        agent: { agent_id: "dashboard_demo" },
        action: { type: "tool_call", tool: "file_read" },
        context: { session_id: session },
      }),
    });
    await api(`${root}/v1/evaluate`, apiKey, {
      method: "POST",
      body: JSON.stringify({
        agent: { agent_id: "dashboard_demo" },
        action: { type: "tool_call", tool: "http_request", destination: "https://example.com" },
        context: { session_id: session },
      }),
    });
    await refresh();
  }

  async function checkout(plan: string) {
    setError("");
    try {
      const res = await api<{ url: string }>(`${root}/v1/billing/checkout`, apiKey, {
        method: "POST",
        body: JSON.stringify({ plan }),
      });
      if (res.url) window.location.href = res.url;
    } catch (e) {
      setError((e as Error).message);
    }
  }

  async function submitContact(e: React.FormEvent) {
    e.preventDefault();
    setContactBusy(true);
    setContactStatus("");
    try {
      const res = await fetch(`${root}/v1/contact`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          name: contactName,
          email: contactEmail,
          company: contactCompany || undefined,
          message: contactMessage,
          website: "", // honeypot
        }),
      });
      const data = (await res.json()) as { ok?: boolean; error?: string; message?: string };
      if (!res.ok) throw new Error(data.error || res.statusText);
      setContactStatus(data.message || "Sent.");
      setContactMessage("");
    } catch (err) {
      setContactStatus((err as Error).message);
    } finally {
      setContactBusy(false);
    }
  }

  return (
    <div className="app">
      <header className="hero">
        <h1>AgentFirewall</h1>
        <p>
          Real-time AI Agent Security Firewall. Inspect tool calls, MCP, secrets, prompt injection,
          and multi-step trajectories before execution — model-agnostic.
        </p>
      </header>

      <section className="panel" style={{ marginBottom: "1.25rem" }}>
        <h2>Pricing</h2>
        <div className="grid" style={{ gridTemplateColumns: "repeat(auto-fit,minmax(180px,1fr))" }}>
          {plans.map((p) => (
            <div className="row" key={p.id}>
              <div>
                <strong>{p.name}</strong>{" "}
                <span className="mono">
                  {p.price_usd_month === 0 ? "Free" : `$${p.price_usd_month}/mo`}
                </span>
              </div>
              <div className="muted">{p.description}</div>
              <ul className="muted" style={{ margin: "0.5rem 0", paddingLeft: "1.1rem" }}>
                {p.features?.map((f) => (
                  <li key={f}>{f}</li>
                ))}
              </ul>
              {p.id !== "developer" ? (
                <button type="button" onClick={() => void checkout(p.id)} disabled={!p.checkout_ready}>
                  {p.checkout_ready ? "Checkout" : "Price pending"}
                </button>
              ) : (
                <span className="muted">Included</span>
              )}
            </div>
          ))}
        </div>
      </section>

      <section className="panel" style={{ marginBottom: "1.25rem" }}>
        <h2>Contact</h2>
        <p className="muted" style={{ marginTop: 0 }}>
          Questions about Pro, Business, or Enterprise? Send a message — delivered via Resend to our
          team inbox (your address stays private on reply).
          {!contactReady ? " (Email delivery not fully configured on this server yet.)" : null}
        </p>
        <form onSubmit={(ev) => void submitContact(ev)} style={{ display: "grid", gap: "0.75rem", maxWidth: 520 }}>
          <label>
            Name
            <input required value={contactName} onChange={(e) => setContactName(e.target.value)} />
          </label>
          <label>
            Email
            <input
              required
              type="email"
              value={contactEmail}
              onChange={(e) => setContactEmail(e.target.value)}
            />
          </label>
          <label>
            Company (optional)
            <input value={contactCompany} onChange={(e) => setContactCompany(e.target.value)} />
          </label>
          <label>
            Message
            <textarea
              required
              rows={4}
              value={contactMessage}
              onChange={(e) => setContactMessage(e.target.value)}
              style={{ width: "100%", font: "inherit", padding: "0.5rem" }}
            />
          </label>
          {/* honeypot */}
          <input
            tabIndex={-1}
            autoComplete="off"
            aria-hidden
            style={{ position: "absolute", left: "-9999px" }}
            name="website"
          />
          <button type="submit" disabled={contactBusy || !contactReady}>
            {contactBusy ? "Sending…" : "Send message"}
          </button>
          {contactStatus ? <p className="muted">{contactStatus}</p> : null}
        </form>
      </section>

      <div className="bar">
        <label>
          API base (blank = same origin / vite proxy)
          <input value={base} onChange={(e) => setBase(e.target.value)} placeholder="http://localhost:8787" />
        </label>
        <label>
          API key
          <input value={apiKey} onChange={(e) => setApiKey(e.target.value)} />
        </label>
        <button type="button" onClick={() => void refresh()} disabled={busy}>
          Refresh
        </button>
        <button type="button" className="secondary" onClick={() => void demoEval()}>
          Demo shell
        </button>
        <button type="button" className="secondary" onClick={() => void demoTrajectory()}>
          Demo trajectory
        </button>
      </div>

      {error ? <p className="muted">Error: {error}</p> : null}

      <div className="grid">
        <section className="panel">
          <h2>Audit log</h2>
          {audit.length === 0 ? <p className="muted">No events yet.</p> : null}
          {audit.map((e) => (
            <div className="row" key={e.id}>
              <div>
                <span className={`pill ${e.decision}`}>{e.decision}</span>{" "}
                <span className="mono">{e.tool ?? e.kind}</span> · risk {e.risk_score}
              </div>
              <div className="muted">
                {e.agent_id} · {e.timestamp}
                {e.session_id ? ` · session ${e.session_id}` : ""}
              </div>
              <div>{e.explanation}</div>
            </div>
          ))}
        </section>

        <div style={{ display: "grid", gap: "1rem" }}>
          <section className="panel">
            <h2>Pending approvals</h2>
            {approvals.length === 0 ? <p className="muted">Nothing waiting.</p> : null}
            {approvals.map((a) => (
              <div className="row" key={a.id}>
                <div className="mono">{a.action_summary}</div>
                <div className="muted">
                  {a.agent_id} · {a.id}
                </div>
                <div className="actions">
                  <button type="button" className="ok" onClick={() => void resolve(a.id, "approved")}>
                    Approve
                  </button>
                  <button type="button" className="no" onClick={() => void resolve(a.id, "denied")}>
                    Deny
                  </button>
                </div>
              </div>
            ))}
          </section>

          <section className="panel">
            <h2>Active policies</h2>
            {rules.length === 0 ? <p className="muted">No rules loaded.</p> : null}
            {rules.map((r) => (
              <div className="row" key={r.id}>
                <div>
                  <span className={`pill ${r.effect}`}>{r.effect}</span>{" "}
                  <span className="mono">{r.id}</span>
                  {!r.enabled ? <span className="muted"> · disabled</span> : null}
                </div>
                <div className="muted">{r.name}</div>
              </div>
            ))}
          </section>
        </div>
      </div>
    </div>
  );
}
