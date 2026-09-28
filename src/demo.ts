import { generateKeyPair } from "jose";
import { verifyEntries } from "./audit.js";
import { CredentialIssuer } from "./credentials.js";
import { AUDIENCE, ISSUER, createEnvironment } from "./environment.js";
import type { InvokeResult } from "./gateway.js";

/**
 * Walks through the scenarios this repo exists to demonstrate. No model and
 * no API key involved: the point is that enforcement does not depend on one.
 *
 * Run with:  npm run demo
 */

let clock = new Date("2026-01-01T09:00:00Z");
const env = await createEnvironment({ now: () => clock });

function show(label: string, r: InvokeResult): void {
  const outcome =
    r.status === "OK"
      ? "EXECUTED"
      : r.status === "PENDING_APPROVAL"
        ? `PENDING APPROVAL  [${r.ruleId}]`
        : r.status === "DENIED"
          ? `DENIED            [${r.ruleId}]`
          : `ERROR             ${r.reason}`;
  console.log(`  ${label.padEnd(58)} ${outcome}`);
}

const supportToken = await env.issuer.issue(
  { agentId: "support-agent", scopes: ["clients:read"], ttlSeconds: 300 },
  clock
);
const paymentsToken = await env.issuer.issue(
  {
    agentId: "payments-agent",
    scopes: ["clients:read", "payments:write"],
    ttlSeconds: 300,
    limits: { maxAmount: 5000 },
  },
  clock
);

console.log("\n== 1. Legitimate use ==");
show("support-agent reads a client record", await env.gateway.invoke(supportToken, "read_client_record", { clientId: "c-100" }));
show("payments-agent transfers 200", await env.gateway.invoke(paymentsToken, "transfer_funds", { amount: 200, toAccount: "acc-1" }));

console.log("\n== 2. A prompt-injected agent tries to exceed its credential ==");
console.log("  (Imagine support-agent read a poisoned document telling it to move money.)");
show(
  "support-agent -> transfer 500 to attacker-account",
  await env.gateway.invoke(supportToken, "transfer_funds", { amount: 500, toAccount: "attacker-account" })
);
console.log("  The model's intent is irrelevant: the credential has no payments scope.");

console.log("\n== 3. Limits and human approval ==");
show("payments-agent transfers 2500 (above approval threshold)", await env.gateway.invoke(paymentsToken, "transfer_funds", { amount: 2500 }));
show("payments-agent transfers 9000 (above its credential limit)", await env.gateway.invoke(paymentsToken, "transfer_funds", { amount: 9000 }));
show("payments-agent transfers -50 (negative amount)", await env.gateway.invoke(paymentsToken, "transfer_funds", { amount: -50 }));
show("payments-agent transfers '100' (string, not a number)", await env.gateway.invoke(paymentsToken, "transfer_funds", { amount: "100" }));
show("payments-agent calls an unregistered tool", await env.gateway.invoke(paymentsToken, "delete_everything", {}));

console.log("\n== 4. Forged and tampered credentials ==");
const [h, p, s] = supportToken.split(".") as [string, string, string];
const payload = JSON.parse(Buffer.from(p, "base64url").toString());
payload.scopes = ["clients:read", "payments:write"];
const tampered = `${h}.${Buffer.from(JSON.stringify(payload)).toString("base64url")}.${s}`;
show("support-agent token edited to add payments:write", await env.gateway.invoke(tampered, "transfer_funds", { amount: 10 }));

const attacker = await generateKeyPair("EdDSA");
const forged = await new CredentialIssuer(attacker.privateKey, ISSUER, AUDIENCE).issue(
  { agentId: "payments-agent", scopes: ["payments:write"], ttlSeconds: 300, limits: { maxAmount: 1e9 } },
  clock
);
show("token minted by an attacker's own key", await env.gateway.invoke(forged, "transfer_funds", { amount: 10 }));

console.log("\n== 5. Expiry and revocation ==");
clock = new Date(clock.getTime() + 10 * 60 * 1000);
show("support-agent reuses its token 10 minutes later", await env.gateway.invoke(supportToken, "read_client_record", { clientId: "c-100" }));

const freshPayments = await env.issuer.issue(
  { agentId: "payments-agent", scopes: ["payments:write"], ttlSeconds: 300, limits: { maxAmount: 5000 } },
  clock
);
show("payments-agent, fresh credential (before kill switch)", await env.gateway.invoke(freshPayments, "transfer_funds", { amount: 100 }));
env.revocations.revokeAgent("payments-agent");
show("payments-agent, same credential (after kill switch)", await env.gateway.invoke(freshPayments, "transfer_funds", { amount: 100 }));

console.log("\n== 6. Audit log ==");
const entries = env.audit.entries();
console.log("  seq  agent            tool                decision          rule");
for (const e of entries) {
  console.log(
    `  ${String(e.seq).padEnd(4)} ${e.agentId.padEnd(16)} ${e.tool.padEnd(19)} ${e.decision.padEnd(17)} ${e.ruleId}`
  );
}
const v = env.audit.verify();
console.log(`\n  chain verifies: ${v.valid}${v.valid ? `  (head ${v.headHash.slice(0, 16)}...)` : ""}`);

const forgedHistory = entries.map((e) => ({ ...e }));
const firstDeny = forgedHistory.find((e) => e.decision === "DENY")!;
firstDeny.decision = "ALLOW";
const tamperCheck = verifyEntries(forgedHistory);
console.log(
  `  after rewriting entry ${firstDeny.seq} from DENY to ALLOW: valid=${tamperCheck.valid}` +
    (tamperCheck.valid ? "" : `  (broken at seq ${tamperCheck.brokenAtSeq}: ${tamperCheck.problem})`)
);
console.log("\n  Note: entries store an args digest, never raw arguments. See README for limits.\n");
