import { AuditLog, canonicalJson, sha256Hex } from "./audit.js";
import {
  verifyCredential,
  type ExpectedIdentity,
  type RevocationList,
  type VerifyKey,
} from "./credentials.js";
import { evaluatePolicy, type PolicyMap, type ToolPolicy } from "./policy.js";

/**
 * The single choke point every agent tool call goes through:
 *
 *   token + tool + args
 *     1. snapshot args to plain JSON   (what is checked is exactly what runs)
 *     2. verify the credential         (signature, expiry, audience, revocation)
 *     3. evaluate deterministic policy (default deny)
 *     4. write the decision to the audit log
 *     5. only then execute the tool
 *
 * Step 4 happens BEFORE step 5 on purpose: a tool that crashes or hangs
 * cannot erase the evidence that the attempt was made and allowed.
 *
 * Nothing in this path calls a model. A prompt-injected agent can ask for
 * anything; the answer depends only on its credential and the policy.
 */

export interface ToolDefinition {
  policy: ToolPolicy;
  handler: (args: Readonly<Record<string, unknown>>) => Promise<unknown> | unknown;
}

export type InvokeResult =
  | { status: "OK"; result: unknown }
  | { status: "DENIED"; ruleId: string; reason: string }
  | { status: "PENDING_APPROVAL"; ruleId: string; reason: string }
  | { status: "ERROR"; reason: string };

export interface GatewayDeps {
  publicKey: VerifyKey;
  expected: ExpectedIdentity;
  revocations: RevocationList;
  audit: AuditLog;
  tools: ToolDefinition[];
  now?: () => Date;
}

type Snapshot = { ok: true; value: Record<string, unknown> } | { ok: false };

/**
 * Round-trip through JSON. This (a) rejects things that aren't plain data
 * (BigInt, circular references), (b) turns NaN/Infinity into null so numeric
 * checks fail closed, and (c) reads every property exactly once -- so a
 * getter that returns a small value for the policy check and a large one for
 * execution cannot slip through (a time-of-check / time-of-use bug).
 */
function snapshotArgs(args: unknown): Snapshot {
  try {
    const json = JSON.stringify(args);
    if (json === undefined) return { ok: false };
    const parsed: unknown = JSON.parse(json);
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      return { ok: false };
    }
    return { ok: true, value: parsed as Record<string, unknown> };
  } catch {
    return { ok: false };
  }
}

export class ToolGateway {
  private readonly policies: Map<string, ToolPolicy> = new Map();
  private readonly handlers: Map<string, ToolDefinition["handler"]> = new Map();
  private readonly now: () => Date;

  constructor(private readonly deps: GatewayDeps) {
    this.now = deps.now ?? (() => new Date());
    for (const tool of deps.tools) {
      if (this.policies.has(tool.policy.tool)) {
        // Misconfiguration should fail loudly at startup, not silently pick one.
        throw new Error(`duplicate tool registered: ${tool.policy.tool}`);
      }
      this.policies.set(tool.policy.tool, tool.policy);
      this.handlers.set(tool.policy.tool, tool.handler);
    }
  }

  async invoke(token: string, tool: string, args: unknown): Promise<InvokeResult> {
    const { audit } = this.deps;
    const snapshot = snapshotArgs(args);
    const argsDigest = snapshot.ok ? sha256Hex(canonicalJson(snapshot.value)) : "unhashable";

    // 1. Credential
    const verified = await verifyCredential(
      token,
      this.deps.publicKey,
      this.deps.expected,
      this.deps.revocations,
      this.now()
    );
    if (!verified.ok) {
      audit.append({
        agentId: verified.verifiedAgentId ?? "unverified",
        tool,
        decision: "DENY",
        ruleId: `C-${verified.reason}`,
        reason: verified.detail,
        argsDigest,
      });
      return { status: "DENIED", ruleId: `C-${verified.reason}`, reason: `credential rejected (${verified.reason})` };
    }
    const { claims } = verified;

    // 2. Arguments must be plain JSON data
    if (!snapshot.ok) {
      audit.append({
        agentId: claims.agentId,
        tool,
        decision: "DENY",
        ruleId: "A-invalid-args",
        reason: "arguments are not a plain JSON object",
        argsDigest,
      });
      return { status: "DENIED", ruleId: "A-invalid-args", reason: "arguments are not a plain JSON object" };
    }

    // 3. Policy
    const decision = evaluatePolicy(this.policies as PolicyMap, claims, tool, snapshot.value);
    audit.append({
      agentId: claims.agentId,
      tool,
      decision: decision.effect,
      ruleId: decision.ruleId,
      reason: decision.reason,
      argsDigest,
    });

    if (decision.effect === "DENY") {
      return { status: "DENIED", ruleId: decision.ruleId, reason: decision.reason };
    }
    if (decision.effect === "REQUIRE_APPROVAL") {
      // The gateway does not execute. An approval workflow would hook in here.
      return { status: "PENDING_APPROVAL", ruleId: decision.ruleId, reason: decision.reason };
    }

    // 4. Execute (decision is already on the record)
    const handler = this.handlers.get(tool)!;
    try {
      return { status: "OK", result: await handler(snapshot.value) };
    } catch (e) {
      audit.append({
        agentId: claims.agentId,
        tool,
        decision: "EXECUTION_ERROR",
        ruleId: "X-execution-error",
        // Constructor name only: error messages can carry sensitive data.
        reason: e instanceof Error ? e.constructor.name : "non-Error thrown",
        argsDigest,
      });
      return { status: "ERROR", reason: "tool execution failed" };
    }
  }
}
