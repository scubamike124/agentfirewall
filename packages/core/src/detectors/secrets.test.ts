import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { detectSecrets } from "./secrets.js";

/** Built at runtime so VCS secret scanners do not treat fixtures as live credentials. */
const OPENAI = ["sk-", "abcdefghijklmnopqrstuvwxyz0123456789"].join("");
const GITHUB_PAT = ["ghp_", "abcdefghijklmnopqrstuvwxyz0123456789"].join("");
const SLACK = ["xox", "b-", "1234567890-", "abcdefghijklmnop"].join("");
const STRIPE = ["sk_", "live_", "51ABCDEF", "ghijklmnopqrstuv"].join("");

describe("detectSecrets hardening", () => {
  it("detects classic OpenAI key", () => {
    const f = detectSecrets([{ body: `key=${OPENAI}` }]);
    assert.ok(f.some((x) => x.code === "secret.openai"));
  });

  it("detects GitHub PAT", () => {
    const f = detectSecrets([{ body: GITHUB_PAT }]);
    assert.ok(f.some((x) => x.code === "secret.github_pat" && x.severity === "critical"));
  });

  it("detects Slack token", () => {
    const f = detectSecrets([{ body: SLACK }]);
    assert.ok(f.some((x) => x.code === "secret.slack" && x.severity === "critical"));
  });

  it("detects password assignment", () => {
    const f = detectSecrets([{ body: 'password="SuperSecretPass123!"' }]);
    assert.ok(f.some((x) => x.code === "secret.password_assignment" && x.severity === "critical"));
  });

  it("detects base64-encoded OpenAI key", () => {
    const body = Buffer.from(OPENAI).toString("base64");
    const f = detectSecrets([{ body }]);
    assert.ok(f.some((x) => x.code === "secret.openai"), `codes=${f.map((x) => x.code)}`);
  });

  it("detects fragmented OpenAI key across fields", () => {
    const f = detectSecrets([{ part1: "sk-abcdef", part2: "ghijklmnopqrstuvwxyz0123456789" }]);
    assert.ok(f.some((x) => x.code === "secret.openai"), `codes=${f.map((x) => x.code)}`);
  });

  it("detects zero-width obfuscated OpenAI key", () => {
    const f = detectSecrets([{ body: "sk-\u200babcdefghijklmnopqrstuvwxyz0123456789" }]);
    assert.ok(f.some((x) => x.code === "secret.openai"), `codes=${f.map((x) => x.code)}`);
  });

  it("detects hex-encoded OpenAI key", () => {
    const body = Buffer.from(OPENAI).toString("hex");
    const f = detectSecrets([{ body }]);
    assert.ok(f.some((x) => x.code === "secret.openai"), `codes=${f.map((x) => x.code)}`);
  });

  it("detects URL-encoded OpenAI key", () => {
    const f = detectSecrets([{ body: "sk%2Dabcdefghijklmnopqrstuvwxyz0123456789" }]);
    assert.ok(f.some((x) => x.code === "secret.openai"), `codes=${f.map((x) => x.code)}`);
  });

  it("detects fullwidth hyphen obfuscation", () => {
    // U+FF0D fullwidth hyphen-minus between sk and rest
    const f = detectSecrets([{ body: `sk\uFF0Dabcdefghijklmnopqrstuvwxyz0123456789` }]);
    assert.ok(f.some((x) => x.code === "secret.openai"), `codes=${f.map((x) => x.code)}`);
  });

  it("detects Stripe-shaped key", () => {
    const f = detectSecrets([{ body: STRIPE }]);
    assert.ok(f.some((x) => x.code === "secret.stripe"));
  });

  it("does not flag benign weather search", () => {
    const f = detectSecrets([{ q: "weather seattle" }]);
    assert.equal(f.length, 0);
  });
});
