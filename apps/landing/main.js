const API = "https://api.agentfirewall.launchreadyal.com";

const form = document.getElementById("contact-form");
const statusEl = document.getElementById("form-status");
const planSelect = document.getElementById("plan-interest");

document.querySelectorAll("[data-plan]").forEach((el) => {
  el.addEventListener("click", (ev) => {
    const plan = el.getAttribute("data-plan");
    if (plan && planSelect) planSelect.value = plan;
    if (el.hasAttribute("data-checkout")) {
      ev.preventDefault();
      startCheckout(plan);
    }
  });
});

const freeBtn = document.getElementById("start-free");
const freeBtn2 = document.getElementById("start-free-price");
freeBtn?.addEventListener("click", (ev) => {
  ev.preventDefault();
  startFree();
});
freeBtn2?.addEventListener("click", (ev) => {
  ev.preventDefault();
  startFree();
});

async function startFree() {
  const email = window.prompt("Work email for your free Developer API key:");
  if (!email) return;
  const name = window.prompt("Your name (optional):") || undefined;
  try {
    const res = await fetch(`${API}/v1/signup`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email, name }),
    });
    const json = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(json.error || `Signup failed (${res.status})`);
    if (json.api_key) {
      window.prompt("Your API key (copied to this dialog — also emailed):", json.api_key);
    } else {
      alert(json.message || "Check your email for your API key.");
    }
  } catch (err) {
    alert(err instanceof Error ? err.message : String(err));
  }
}

async function startCheckout(planLabel) {
  const plan = String(planLabel || "").toLowerCase();
  if (!["pro", "business", "enterprise"].includes(plan)) return;
  const email = window.prompt(`Work email for ${planLabel} checkout:`);
  if (!email) return;
  try {
    const res = await fetch(`${API}/v1/billing/checkout`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ plan, email }),
    });
    const json = await res.json().catch(() => ({}));
    if (!res.ok || !json.url) throw new Error(json.error || `Checkout failed (${res.status})`);
    window.location.href = json.url;
  } catch (err) {
    alert(err instanceof Error ? err.message : String(err));
  }
}

form?.addEventListener("submit", async (e) => {
  e.preventDefault();
  statusEl.textContent = "Sending…";
  statusEl.className = "form-status";

  const fd = new FormData(form);
  const plan = String(fd.get("plan") || "").trim();
  const baseMessage = String(fd.get("message") || "").trim();
  const body = {
    name: String(fd.get("name") || "").trim(),
    email: String(fd.get("email") || "").trim(),
    company: String(fd.get("company") || "").trim() || undefined,
    message: plan ? `[Plan interest: ${plan}]\n\n${baseMessage}` : baseMessage,
    website: String(fd.get("website") || ""),
  };

  try {
    const res = await fetch(`${API}/v1/contact`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    const json = await res.json().catch(() => ({}));
    if (!res.ok) {
      throw new Error(json.error || `Send failed (${res.status})`);
    }
    statusEl.textContent = json.message || "Sent.";
    statusEl.className = "form-status ok";
    form.reset();
  } catch (err) {
    statusEl.textContent = err instanceof Error ? err.message : String(err);
    statusEl.className = "form-status err";
  }
});
