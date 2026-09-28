import { describe, test } from "node:test";
import assert from "node:assert/strict";
import { evaluatePolicy, type ToolPolicy } from "../src/policy.js";
import type { AgentClaims } from "../src/credentials.js";

const policies = new Map<string, ToolPolicy>([
  ["read_client_record", { tool: "read_client_record", requiredScope: "clients:read" }],
  [
    "transfer_funds",
    { tool: "transfer_funds", requiredScope: "payments:write", amountArg: "amount", approvalAbove: 1000 },
  ],
]);

function claims(over: Partial<AgentClaims> = {}): AgentClaims {
  return {
    agentId: "agent-a",
    scopes: ["clients:read", "payments:write"],
    limits: { maxAmount: 5000 },
    jti: "j1",
    expiresAt: new Date("2030-01-01"),
    ...over,
  };
}

const decide = (c: AgentClaims, tool: string, args: Record<string, unknown> = {}) =>
  evaluatePolicy(policies, c, tool, args);

describe("policy: default deny and scopes", () => {
  test("an unregistered tool is denied (R1)", () => {
    const d = decide(claims(), "drop_database");
    assert.equal(d.effect, "DENY");
    assert.equal(d.ruleId, "R1-default-deny");
  });

  test("a missing scope is denied (R2)", () => {
    const d = decide(claims({ scopes: ["clients:read"] }), "transfer_funds", { amount: 10 });
    assert.equal(d.effect, "DENY");
    assert.equal(d.ruleId, "R2-missing-scope");
  });

  test("scope matching is exact: prefixes, supersets and case variants do not count", () => {
    for (const scope of ["payments", "payments:", "payments:write:extra", "PAYMENTS:WRITE", "*", "payments:*"]) {
      const d = decide(claims({ scopes: [scope] }), "transfer_funds", { amount: 10 });
      assert.equal(d.ruleId, "R2-missing-scope", `scope ${JSON.stringify(scope)} must not satisfy payments:write`);
    }
  });

  test("a non-amount tool is allowed with the right scope (R6)", () => {
    const d = decide(claims(), "read_client_record", { clientId: "c1" });
    assert.equal(d.effect, "ALLOW");
    assert.equal(d.ruleId, "R6-allow");
  });
});

describe("policy: amounts fail closed", () => {
  test("missing, non-numeric, zero, negative and non-finite amounts are denied (R3)", () => {
    const bad: unknown[] = [undefined, null, "100", "abc", "", 0, -5, -0.01, Number.NaN, Infinity, -Infinity, {}, [], true];
    for (const amount of bad) {
      const d = decide(claims(), "transfer_funds", amount === undefined ? {} : { amount });
      assert.equal(d.effect, "DENY", `amount ${String(amount)}`);
      assert.equal(d.ruleId, "R3-invalid-amount", `amount ${String(amount)}`);
    }
  });

  test("a credential with no limit cannot make amount-bearing calls (R4)", () => {
    const d = decide(claims({ limits: {} }), "transfer_funds", { amount: 1 });
    assert.equal(d.effect, "DENY");
    assert.equal(d.ruleId, "R4-over-credential-limit");
  });

  test("an amount above the credential's own limit is denied (R4)", () => {
    const d = decide(claims({ limits: { maxAmount: 100 } }), "transfer_funds", { amount: 100.01 });
    assert.equal(d.effect, "DENY");
    assert.equal(d.ruleId, "R4-over-credential-limit");
  });

  test("the limit boundary is inclusive: exactly the limit is not denied", () => {
    const d = decide(claims({ limits: { maxAmount: 100 } }), "transfer_funds", { amount: 100 });
    assert.notEqual(d.effect, "DENY");
  });
});

describe("policy: approval threshold", () => {
  test("above the threshold but within the limit requires approval (R5)", () => {
    const d = decide(claims(), "transfer_funds", { amount: 2500 });
    assert.equal(d.effect, "REQUIRE_APPROVAL");
    assert.equal(d.ruleId, "R5-approval-required");
  });

  test("exactly at the threshold is allowed; one cent above needs approval", () => {
    assert.equal(decide(claims(), "transfer_funds", { amount: 1000 }).effect, "ALLOW");
    assert.equal(decide(claims(), "transfer_funds", { amount: 1000.01 }).effect, "REQUIRE_APPROVAL");
  });

  test("the credential limit is checked before the approval threshold (a human cannot approve past the limit)", () => {
    const d = decide(claims({ limits: { maxAmount: 2000 } }), "transfer_funds", { amount: 3000 });
    assert.equal(d.effect, "DENY");
    assert.equal(d.ruleId, "R4-over-credential-limit");
  });

  test("a small amount within limits is allowed", () => {
    assert.equal(decide(claims(), "transfer_funds", { amount: 200 }).effect, "ALLOW");
  });
});
