import type { ToolDefinition } from "./gateway.js";

/**
 * Stub tools with synthetic data, standing in for real integrations.
 * The point of the repo is the enforcement layer around them, not the tools.
 */
export const exampleTools: ToolDefinition[] = [
  {
    policy: { tool: "read_client_record", requiredScope: "clients:read" },
    handler: (args) => ({ clientId: args["clientId"], name: "(synthetic) J. Harper", segment: "retail" }),
  },
  {
    policy: { tool: "send_email", requiredScope: "email:send" },
    handler: (args) => ({ queued: true, to: args["to"] }),
  },
  {
    policy: {
      tool: "transfer_funds",
      requiredScope: "payments:write",
      amountArg: "amount",
      approvalAbove: 1000,
    },
    handler: (args) => ({ transferred: args["amount"], to: args["toAccount"] }),
  },
];
