import { serve } from "@hono/node-server";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { createApp } from "./app.js";

/** Load monorepo / cwd .env without printing secrets. */
function loadEnvFile(file: string) {
  if (!fs.existsSync(file)) return;
  for (const line of fs.readFileSync(file, "utf8").split(/\r?\n/)) {
    const m = line.match(/^([^#=]+)=(.*)$/);
    if (!m) continue;
    const k = m[1].trim();
    let v = m[2].trim();
    if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) {
      v = v.slice(1, -1);
    }
    if (!process.env[k]) process.env[k] = v;
  }
}

const here = path.dirname(fileURLToPath(import.meta.url));
loadEnvFile(path.resolve(here, "../../../.env"));
loadEnvFile(path.resolve(process.cwd(), ".env"));
loadEnvFile(path.resolve(process.cwd(), ".env.local"));

const PORT = Number(process.env.PORT ?? 8787);
const app = createApp();

console.log(`AgentFirewall API listening on http://localhost:${PORT}`);
console.log(`API key: set AGENTFIREWALL_API_KEY (default af_dev_key_change_me)`);
serve({ fetch: app.fetch, port: PORT });
