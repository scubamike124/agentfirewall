import fs from "node:fs";

const before = JSON.parse(fs.readFileSync("proofs/results/proof_2026-08-10T01-40-59-041Z.json", "utf8"));
const after = JSON.parse(fs.readFileSync("proofs/results/latest.json", "utf8"));
const miss = [
  "sec.github.1",
  "sec.slack.1",
  "sec.pwd.1",
  "sec.b64.1",
  "sec.split.1",
  "sec.zw.1",
  "sec.hex.1",
  "sec.url.1",
];

function row(r) {
  return {
    decision: r.decision,
    matched: r.matched,
    secret_codes: (r.findings || [])
      .filter((f) => (f.code || "").startsWith("secret."))
      .map((f) => f.code),
    evaluation_id: r.evaluation_id,
  };
}

for (const id of miss) {
  const b = before.cases.find((c) => c.id === id);
  const a = after.cases.find((c) => c.id === id);
  console.log(id);
  console.log("  BEFORE", JSON.stringify(row(b)));
  console.log("  AFTER ", JSON.stringify(row(a)));
}

const ba = before.cases.filter((c) => c.category !== "normal_traffic");
const aa = after.cases.filter((c) => ba.some((b) => b.id === c.id));
console.log(
  "\noriginal corpus",
  `${before.summary.attack_blocked_or_held}/${before.summary.attack_total}`,
  "->",
  `${aa.filter((c) => c.matched).length}/${aa.length}`,
);
console.log("full after", `${after.summary.attack_blocked_or_held}/${after.summary.attack_total}`);
console.log("secrets", after.by_category.secret_exfiltration);
console.log(
  "unseen",
  after.cases.filter((c) => String(c.id).startsWith("sec.unseen")).map((u) => `${u.id}:${u.decision}`),
);
console.log("fp", `${after.summary.benign_false_positives}/${after.summary.benign_total}`);
