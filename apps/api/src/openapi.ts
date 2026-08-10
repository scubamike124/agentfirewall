/** Minimal OpenAPI 3 document for AgentFirewall MVP. */
export const openApiDocument = {
  openapi: "3.0.3",
  info: {
    title: "AgentFirewall API",
    version: "0.1.0",
    description:
      "Real-time AI Agent Security Firewall. Evaluate tool/MCP/API actions before execution. Model-agnostic.",
  },
  servers: [{ url: "http://localhost:8787" }],
  components: {
    securitySchemes: {
      ApiKeyAuth: {
        type: "http",
        scheme: "bearer",
        description: "Customer API key (AGENTFIREWALL_API_KEY)",
      },
    },
    schemas: {
      Decision: { type: "string", enum: ["allow", "block", "approval_required"] },
      Agent: {
        type: "object",
        required: ["agent_id"],
        properties: {
          agent_id: { type: "string" },
          display_name: { type: "string" },
          scopes: { type: "array", items: { type: "string" } },
          org_id: { type: "string" },
        },
      },
      Action: {
        type: "object",
        required: ["type", "tool"],
        properties: {
          type: { type: "string", example: "tool_call" },
          tool: { type: "string" },
          parameters: { type: "object", additionalProperties: true },
          destination: { type: "string" },
          amount: { type: "number" },
          currency: { type: "string" },
        },
      },
      EvaluateRequest: {
        type: "object",
        required: ["agent", "action"],
        properties: {
          agent: { $ref: "#/components/schemas/Agent" },
          action: { $ref: "#/components/schemas/Action" },
          context: {
            type: "object",
            properties: {
              session_id: { type: "string" },
              prior_actions: { type: "array", items: { $ref: "#/components/schemas/Action" } },
              untrusted_content: { type: "array", items: { type: "string" } },
              mcp_descriptions: { type: "array", items: { type: "string" } },
              messages: { type: "array", items: { type: "string" } },
            },
          },
          destination: { type: "string" },
        },
      },
      EvaluateResponse: {
        type: "object",
        properties: {
          evaluation_id: { type: "string" },
          decision: { $ref: "#/components/schemas/Decision" },
          risk_score: { type: "number" },
          risk_level: { type: "string" },
          explanation: { type: "string" },
          findings: { type: "array", items: { type: "object" } },
          policy_ids: { type: "array", items: { type: "string" } },
          approval_id: { type: "string" },
          agent_id: { type: "string" },
          timestamp: { type: "string", format: "date-time" },
        },
      },
    },
  },
  security: [{ ApiKeyAuth: [] }],
  paths: {
    "/health": {
      get: {
        security: [],
        summary: "Health",
        responses: { "200": { description: "OK" } },
      },
    },
    "/v1/evaluate": {
      post: {
        summary: "Evaluate a proposed agent action before execution",
        requestBody: {
          required: true,
          content: { "application/json": { schema: { $ref: "#/components/schemas/EvaluateRequest" } } },
        },
        responses: {
          "200": {
            description: "Decision",
            content: { "application/json": { schema: { $ref: "#/components/schemas/EvaluateResponse" } } },
          },
          "401": { description: "Unauthorized" },
        },
      },
    },
    "/v1/trajectory/evaluate": {
      post: {
        summary: "Evaluate multi-step behavior / trajectory",
        responses: { "200": { description: "Decision" } },
      },
    },
    "/v1/agents": {
      post: {
        summary: "Issue short-lived agent credential",
        responses: { "200": { description: "Credential issued" } },
      },
    },
    "/v1/audit": {
      get: {
        summary: "List audit events",
        responses: { "200": { description: "Audit events" } },
      },
    },
    "/v1/policies": {
      get: { summary: "Get policy config", responses: { "200": { description: "Policy" } } },
      put: { summary: "Replace policy config", responses: { "200": { description: "Saved" } } },
    },
    "/v1/approvals": {
      get: { summary: "List approvals", responses: { "200": { description: "Approvals" } } },
    },
    "/v1/approvals/{id}/resolve": {
      post: {
        summary: "Approve or deny a pending action",
        parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
        responses: { "200": { description: "Resolved" } },
      },
    },
    "/v1/webhooks": {
      get: { summary: "List webhooks", responses: { "200": { description: "Webhooks" } } },
      put: { summary: "Replace webhooks", responses: { "200": { description: "Saved" } } },
    },
    "/v1/sessions/{sessionId}": {
      get: {
        summary: "Get server-side session trajectory",
        parameters: [
          { name: "sessionId", in: "path", required: true, schema: { type: "string" } },
          { name: "agent_id", in: "query", required: true, schema: { type: "string" } },
        ],
        responses: { "200": { description: "Session" } },
      },
      delete: {
        summary: "Clear session trajectory",
        parameters: [
          { name: "sessionId", in: "path", required: true, schema: { type: "string" } },
          { name: "agent_id", in: "query", required: true, schema: { type: "string" } },
        ],
        responses: { "200": { description: "Cleared" } },
      },
    },
    "/v1/openapi.json": {
      get: {
        security: [],
        summary: "OpenAPI document",
        responses: { "200": { description: "OpenAPI JSON" } },
      },
    },
  },
} as const;
