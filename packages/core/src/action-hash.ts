import { createHash } from "crypto";
import type { ProposedAction } from "./types.js";

/** Stable JSON for hashing (sorted keys, no undefined). */
export function canonicalize(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((v) => canonicalize(v)).join(",")}]`;
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalize(obj[k])}`).join(",")}}`;
}

/** Bind an approval to the exact proposed action. */
export function hashAction(action: ProposedAction, destination?: string): string {
  const payload = {
    type: action.type,
    tool: action.tool,
    parameters: action.parameters ?? {},
    destination: destination ?? action.destination ?? null,
    amount: action.amount ?? null,
    currency: action.currency ?? null,
  };
  return createHash("sha256").update(canonicalize(payload)).digest("hex");
}
