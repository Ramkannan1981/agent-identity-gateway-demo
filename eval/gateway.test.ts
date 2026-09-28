import { describe, test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPair } from "jose";
import { CredentialIssuer } from "../src/credentials.js";
import { AUDIENCE, ISSUER, createEnvironment } from "../src/environment.js";
import type { ToolDefinition } from "../src/gateway.js";
import { ToolGateway } from "../src/gateway.js";
import { AuditLog } from "../src/audit.js";
import { RevocationList } from "../src/credentials.js";

/** Tools that record every execution, so tests can prove a denied call NEVER ran. */
function spyTools() {
  const executed: { tool: string; args: Record<string, unknown> }[] = [];
  const mk = (
    tool: string,
    requiredScope: string,
    extra: Partial<ToolDefinition["policy"]> = {}
  ): ToolDefinition => ({
    policy: { tool, requiredScope, ...extra },
    handler: (args) => {
      executed.push({ tool, args: { ...args } });
      return { ok: true };
    },
  });
  const tools = [
    mk("read_client_record", "clients:read"),
    mk("transfer_funds", "payments:write", { amountArg: "amount", approvalAbove: 1000 }),
  ];
  return { tools, executed };
}

async function env() {
  let clock = new Date("2026-01-01T00:00:00Z");
  const spy = spyTools();
  const e = await createEnvironment({ now: () => clock, tools: spy.tools });
  return {
    ...e,
    executed: spy.executed,
    now: () => clock,
    advance: (ms: number) => {
      clock = new Date(clock.getTime() + ms);
    },
  };
}

const readerOpts = { agentId: "support-agent", scopes: ["clients:read"], ttlSeconds: 300 };
const payerOpts = {
  agentId: "payments-agent",
  scopes: ["clients:read", "payments:write"],
  ttlSeconds: 300,
  limits: { maxAmount: 5000 },
};

describe("gateway: the prompt-injection scenario", () => {
  test("an agent with only read scope is denied a transfer, and the tool never runs", async () => {
    const e = await env();
    const token = await e.issuer.issue(readerOpts, e.now());
    // Whatever the model was tricked into wanting, the credential decides.
    const r = await e.gateway.invoke(token, "transfer_funds", { amount: 500, toAccount: "attacker" });
    assert.equal(r.status, "DENIED");
    if (r.status === "DENIED") assert.equal(r.ruleId, "R2-missing-scope");
    assert.equal(e.executed.length, 0);
  });

  test("a credential forged by an attacker with admin scopes is denied and nothing runs", async () => {
    const e = await env();
    const attacker = await generateKeyPair("EdDSA");
    const forged = await new CredentialIssuer(attacker.privateKey, ISSUER, AUDIENCE).issue(
      { agentId: "support-agent", scopes: ["clients:read", "payments:write"], ttlSeconds: 300, limits: { maxAmount: 1e9 } },
      e.now()
    );
    const r = await e.gateway.invoke(forged, "transfer_funds", { amount: 100000, toAccount: "attacker" });
    assert.equal(r.status, "DENIED");
    if (r.status === "DENIED") assert.equal(r.ruleId, "C-BAD_SIGNATURE");
    assert.equal(e.executed.length, 0);
  });
});

describe("gateway: decisions", () => {
  test("a legitimate read is executed", async () => {
    const e = await env();
    const token = await e.issuer.issue(readerOpts, e.now());
    const r = await e.gateway.invoke(token, "read_client_record", { clientId: "c1" });
    assert.equal(r.status, "OK");
    assert.equal(e.executed.length, 1);
  });

  test("transfers: small is executed, mid needs approval (and does not run), large is denied", async () => {
    const e = await env();
    const token = await e.issuer.issue(payerOpts, e.now());

    assert.equal((await e.gateway.invoke(token, "transfer_funds", { amount: 200 })).status, "OK");
    assert.equal(e.executed.length, 1);

    const mid = await e.gateway.invoke(token, "transfer_funds", { amount: 2500 });
    assert.equal(mid.status, "PENDING_APPROVAL");
    assert.equal(e.executed.length, 1, "an approval-required call must not execute");

    const big = await e.gateway.invoke(token, "transfer_funds", { amount: 9000 });
    assert.equal(big.status, "DENIED");
    if (big.status === "DENIED") assert.equal(big.ruleId, "R4-over-credential-limit");
    assert.equal(e.executed.length, 1);
  });

  test("an unknown tool is denied by default", async () => {
    const e = await env();
    const token = await e.issuer.issue(payerOpts, e.now());
    const r = await e.gateway.invoke(token, "delete_everything", {});
    assert.equal(r.status, "DENIED");
    if (r.status === "DENIED") assert.equal(r.ruleId, "R1-default-deny");
  });

  test("an expired credential is denied once the clock moves past expiry", async () => {
    const e = await env();
    const token = await e.issuer.issue(readerOpts, e.now());
    assert.equal((await e.gateway.invoke(token, "read_client_record", { clientId: "c1" })).status, "OK");
    e.advance(301_000);
    const r = await e.gateway.invoke(token, "read_client_record", { clientId: "c1" });
    assert.equal(r.status, "DENIED");
    if (r.status === "DENIED") assert.equal(r.ruleId, "C-EXPIRED");
    assert.equal(e.executed.length, 1);
  });

  test("revoking an agent takes effect on the very next call", async () => {
    const e = await env();
    const token = await e.issuer.issue(readerOpts, e.now());
    assert.equal((await e.gateway.invoke(token, "read_client_record", { clientId: "c1" })).status, "OK");
    e.revocations.revokeAgent("support-agent");
    const r = await e.gateway.invoke(token, "read_client_record", { clientId: "c1" });
    assert.equal(r.status, "DENIED");
    if (r.status === "DENIED") assert.equal(r.ruleId, "C-REVOKED");
  });

  test("arguments that are not plain JSON objects are denied", async () => {
    const e = await env();
    const token = await e.issuer.issue(readerOpts, e.now());
    const circular: Record<string, unknown> = {};
    circular["self"] = circular;
    for (const bad of [circular, { n: 10n }, [1, 2], null, "string", 42, undefined]) {
      const r = await e.gateway.invoke(token, "read_client_record", bad);
      assert.equal(r.status, "DENIED");
      if (r.status === "DENIED") assert.equal(r.ruleId, "A-invalid-args");
    }
    assert.equal(e.executed.length, 0);
  });
});

describe("gateway: what is checked is what runs", () => {
  test("TOCTOU: a getter that changes value between reads cannot smuggle a larger amount past the policy", async () => {
    const e = await env();
    const token = await e.issuer.issue(payerOpts, e.now());
    let reads = 0;
    const sneaky = {
      get amount() {
        return reads++ === 0 ? 10 : 4000; // small for the check, large for execution
      },
    };
    const r = await e.gateway.invoke(token, "transfer_funds", sneaky);
    assert.equal(r.status, "OK");
    assert.equal(e.executed.length, 1);
    assert.equal(e.executed[0]!.args["amount"], 10, "the handler must receive exactly what the policy evaluated");
  });
});

describe("gateway: audit trail", () => {
  test("every denied call writes exactly one entry, attributed only when the signature was verified", async () => {
    const e = await env();
    const good = await e.issuer.issue(readerOpts, e.now());
    await e.gateway.invoke(good, "transfer_funds", { amount: 1 }); // R2
    await e.gateway.invoke("garbage", "read_client_record", {}); // malformed
    const entries = e.audit.entries();
    assert.equal(entries.length, 2);
    assert.equal(entries[0]!.agentId, "support-agent");
    assert.equal(entries[0]!.decision, "DENY");
    assert.equal(entries[1]!.agentId, "unverified");
  });

  test("the audit log never stores raw arguments, only a digest", async () => {
    const e = await env();
    const token = await e.issuer.issue(readerOpts, e.now());
    await e.gateway.invoke(token, "read_client_record", { clientId: "CLIENT-SECRET-123" });
    const serialised = JSON.stringify(e.audit.entries());
    assert.ok(!serialised.includes("CLIENT-SECRET-123"));
    assert.match(e.audit.entries()[0]!.argsDigest, /^[0-9a-f]{64}$/);
  });

  test("the ALLOW decision is already in the audit log at the moment the tool executes", async () => {
    let auditRef: AuditLog | undefined;
    let seenDuringExecution: string[] = [];
    const tools: ToolDefinition[] = [
      {
        policy: { tool: "read_client_record", requiredScope: "clients:read" },
        handler: () => {
          seenDuringExecution = auditRef!.entries().map((x) => x.decision);
          return { ok: true };
        },
      },
    ];
    const e = await createEnvironment({ tools });
    auditRef = e.audit;
    const token = await e.issuer.issue(readerOpts);
    await e.gateway.invoke(token, "read_client_record", { clientId: "c1" });
    assert.deepEqual(seenDuringExecution, ["ALLOW"], "a tool must not be able to run before its decision is recorded");
  });

  test("a crashing tool adds an error entry after the ALLOW, without leaking its message", async () => {
    const tools: ToolDefinition[] = [
      {
        policy: { tool: "read_client_record", requiredScope: "clients:read" },
        handler: () => {
          throw new Error("db password is hunter2");
        },
      },
    ];
    const e = await createEnvironment({ tools });
    const token = await e.issuer.issue(readerOpts);
    const r = await e.gateway.invoke(token, "read_client_record", { clientId: "c1" });
    assert.equal(r.status, "ERROR");
    const entries = e.audit.entries();
    assert.deepEqual(entries.map((x) => x.decision), ["ALLOW", "EXECUTION_ERROR"]);
    assert.ok(!JSON.stringify(entries).includes("hunter2"));
  });

  test("the chain still verifies after a mixed sequence of calls", async () => {
    const e = await env();
    const token = await e.issuer.issue(payerOpts, e.now());
    await e.gateway.invoke(token, "read_client_record", { clientId: "c1" });
    await e.gateway.invoke(token, "transfer_funds", { amount: 2500 });
    await e.gateway.invoke(token, "transfer_funds", { amount: 9000 });
    await e.gateway.invoke("garbage", "x", {});
    assert.ok(e.audit.verify().valid);
    assert.equal(e.audit.entries().length, 4);
  });
});

describe("gateway: configuration", () => {
  test("registering the same tool twice fails loudly at construction", async () => {
    const { tools } = spyTools();
    const { publicKey } = await generateKeyPair("EdDSA");
    assert.throws(
      () =>
        new ToolGateway({
          publicKey,
          expected: { issuer: ISSUER, audience: AUDIENCE },
          revocations: new RevocationList(),
          audit: new AuditLog(),
          tools: [...tools, tools[0]!],
        }),
      /duplicate tool/
    );
  });
});
