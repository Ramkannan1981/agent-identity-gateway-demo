import { describe, test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPair, SignJWT } from "jose";
import {
  CredentialIssuer,
  RevocationList,
  verifyCredential,
  type VerifyResult,
} from "../src/credentials.js";
import { AUDIENCE, ISSUER } from "../src/environment.js";

const T0 = new Date("2026-01-01T00:00:00Z");
const expected = { issuer: ISSUER, audience: AUDIENCE };

async function setup() {
  const { publicKey, privateKey } = await generateKeyPair("EdDSA");
  const issuer = new CredentialIssuer(privateKey, ISSUER, AUDIENCE);
  return { publicKey, privateKey, issuer, revocations: new RevocationList() };
}

function expectFail(r: VerifyResult) {
  if (r.ok) assert.fail("expected verification to fail");
  return r;
}

function b64url(obj: unknown): string {
  return Buffer.from(JSON.stringify(obj)).toString("base64url");
}

describe("credential verification", () => {
  test("a valid credential verifies and exposes its claims", async () => {
    const { publicKey, issuer, revocations } = await setup();
    const token = await issuer.issue(
      { agentId: "agent-a", scopes: ["clients:read"], ttlSeconds: 60, limits: { maxAmount: 500 } },
      T0
    );
    const r = await verifyCredential(token, publicKey, expected, revocations, T0);
    assert.ok(r.ok);
    assert.equal(r.claims.agentId, "agent-a");
    assert.deepEqual(r.claims.scopes, ["clients:read"]);
    assert.equal(r.claims.limits.maxAmount, 500);
  });

  test("an expired credential is rejected and attributed to its (verified) agent", async () => {
    const { publicKey, issuer, revocations } = await setup();
    const token = await issuer.issue({ agentId: "agent-a", scopes: [], ttlSeconds: 60 }, T0);
    const later = new Date(T0.getTime() + 120_000);
    const r = expectFail(await verifyCredential(token, publicKey, expected, revocations, later));
    assert.equal(r.reason, "EXPIRED");
    assert.equal(r.verifiedAgentId, "agent-a");
  });

  test("a credential is valid right up to expiry and not after", async () => {
    const { publicKey, issuer, revocations } = await setup();
    const token = await issuer.issue({ agentId: "agent-a", scopes: [], ttlSeconds: 60 }, T0);
    const justBefore = new Date(T0.getTime() + 59_000);
    const atExpiry = new Date(T0.getTime() + 60_000);
    assert.ok((await verifyCredential(token, publicKey, expected, revocations, justBefore)).ok);
    assert.equal(
      expectFail(await verifyCredential(token, publicKey, expected, revocations, atExpiry)).reason,
      "EXPIRED"
    );
  });

  test("a payload edited after signing (privilege escalation) fails the signature check", async () => {
    const { publicKey, issuer, revocations } = await setup();
    const token = await issuer.issue({ agentId: "agent-a", scopes: ["clients:read"], ttlSeconds: 60 }, T0);
    const [h, p, s] = token.split(".") as [string, string, string];
    const payload = JSON.parse(Buffer.from(p, "base64url").toString());
    payload.scopes = ["clients:read", "payments:write"];
    const forged = `${h}.${b64url(payload)}.${s}`;
    const r = expectFail(await verifyCredential(forged, publicKey, expected, revocations, T0));
    assert.equal(r.reason, "BAD_SIGNATURE");
    assert.equal(r.verifiedAgentId, undefined, "must not attribute an unverified token to an agent");
  });

  test("a credential signed by a different key is rejected", async () => {
    const { publicKey, revocations } = await setup();
    const attacker = await generateKeyPair("EdDSA");
    const forgedIssuer = new CredentialIssuer(attacker.privateKey, ISSUER, AUDIENCE);
    const token = await forgedIssuer.issue(
      { agentId: "agent-a", scopes: ["payments:write"], ttlSeconds: 60, limits: { maxAmount: 1e9 } },
      T0
    );
    assert.equal(
      expectFail(await verifyCredential(token, publicKey, expected, revocations, T0)).reason,
      "BAD_SIGNATURE"
    );
  });

  test("a credential minted for a different audience is rejected", async () => {
    const { publicKey, privateKey, revocations } = await setup();
    const other = new CredentialIssuer(privateKey, ISSUER, "some-other-service");
    const token = await other.issue({ agentId: "agent-a", scopes: [], ttlSeconds: 60 }, T0);
    assert.equal(
      expectFail(await verifyCredential(token, publicKey, expected, revocations, T0)).reason,
      "INVALID_CLAIMS"
    );
  });

  test("a credential from a different issuer is rejected", async () => {
    const { publicKey, privateKey, revocations } = await setup();
    const other = new CredentialIssuer(privateKey, "https://evil.example.test", AUDIENCE);
    const token = await other.issue({ agentId: "agent-a", scopes: [], ttlSeconds: 60 }, T0);
    assert.equal(
      expectFail(await verifyCredential(token, publicKey, expected, revocations, T0)).reason,
      "INVALID_CLAIMS"
    );
  });

  test("algorithm confusion: an HS256 token is rejected", async () => {
    const { publicKey, revocations } = await setup();
    const token = await new SignJWT({ scopes: ["payments:write"], limits: { maxAmount: 1e9 } })
      .setProtectedHeader({ alg: "HS256" })
      .setSubject("agent-a")
      .setIssuer(ISSUER)
      .setAudience(AUDIENCE)
      .setJti("x")
      .setIssuedAt(Math.floor(T0.getTime() / 1000))
      .setExpirationTime(Math.floor(T0.getTime() / 1000) + 60)
      .sign(new TextEncoder().encode("attacker-chosen-secret-of-sufficient-length"));
    assert.equal(expectFail(await verifyCredential(token, publicKey, expected, revocations, T0)).ok, false);
  });

  test('"alg: none" (unsigned) tokens are rejected', async () => {
    const { publicKey, revocations } = await setup();
    const unsigned = `${b64url({ alg: "none", typ: "JWT" })}.${b64url({
      sub: "agent-a",
      iss: ISSUER,
      aud: AUDIENCE,
      jti: "x",
      iat: Math.floor(T0.getTime() / 1000),
      exp: Math.floor(T0.getTime() / 1000) + 60,
      scopes: ["payments:write"],
      limits: { maxAmount: 1e9 },
    })}.`;
    assert.equal(expectFail(await verifyCredential(unsigned, publicKey, expected, revocations, T0)).ok, false);
  });

  test("a validly signed credential missing sub, jti, exp or iat is rejected (never-expiring / unrevocable tokens are dangerous)", async () => {
    const { publicKey, privateKey, revocations } = await setup();
    const iat = Math.floor(T0.getTime() / 1000);
    for (const omit of ["sub", "jti", "exp", "iat"] as const) {
      let jwt = new SignJWT({ scopes: ["clients:read"], limits: {} })
        .setProtectedHeader({ alg: "EdDSA" })
        .setIssuer(ISSUER)
        .setAudience(AUDIENCE);
      if (omit !== "sub") jwt = jwt.setSubject("agent-a");
      if (omit !== "jti") jwt = jwt.setJti("j1");
      if (omit !== "iat") jwt = jwt.setIssuedAt(iat);
      if (omit !== "exp") jwt = jwt.setExpirationTime(iat + 60);
      const token = await jwt.sign(privateKey);
      const r = expectFail(await verifyCredential(token, publicKey, expected, revocations, T0));
      assert.equal(r.reason, "INVALID_CLAIMS", `omitting ${omit}`);
    }
  });

  test("a validly signed credential with malformed scopes or limits is rejected", async () => {
    const { publicKey, privateKey, revocations } = await setup();
    const iat = Math.floor(T0.getTime() / 1000);
    const cases: Record<string, unknown>[] = [
      { scopes: "payments:write", limits: {} }, // string, not an array
      { scopes: [1, 2], limits: {} }, // not strings
      { scopes: ["clients:read"], limits: [] }, // array, not an object
      { scopes: ["clients:read"], limits: null },
      { limits: {} }, // scopes missing entirely
    ];
    for (const claims of cases) {
      const token = await new SignJWT(claims)
        .setProtectedHeader({ alg: "EdDSA" })
        .setSubject("agent-a")
        .setIssuer(ISSUER)
        .setAudience(AUDIENCE)
        .setJti("j1")
        .setIssuedAt(iat)
        .setExpirationTime(iat + 60)
        .sign(privateKey);
      const r = expectFail(await verifyCredential(token, publicKey, expected, revocations, T0));
      assert.equal(r.reason, "INVALID_CLAIMS", JSON.stringify(claims));
    }
  });

  test("a non-finite or non-numeric maxAmount in the credential is ignored, leaving no limit (which the policy then refuses)", async () => {
    const { publicKey, privateKey, revocations } = await setup();
    const iat = Math.floor(T0.getTime() / 1000);
    const token = await new SignJWT({ scopes: ["payments:write"], limits: { maxAmount: "999999" } })
      .setProtectedHeader({ alg: "EdDSA" })
      .setSubject("agent-a")
      .setIssuer(ISSUER)
      .setAudience(AUDIENCE)
      .setJti("j1")
      .setIssuedAt(iat)
      .setExpirationTime(iat + 60)
      .sign(privateKey);
    const r = await verifyCredential(token, publicKey, expected, revocations, T0);
    assert.ok(r.ok);
    assert.equal(r.claims.limits.maxAmount, undefined);
  });

  test("garbage input is rejected as malformed, not thrown", async () => {
    const { publicKey, revocations } = await setup();
    for (const junk of ["", "not-a-jwt", "a.b.c", "....", "🙂"]) {
      const r = expectFail(await verifyCredential(junk, publicKey, expected, revocations, T0));
      assert.equal(r.reason, "MALFORMED", `input ${JSON.stringify(junk)}`);
    }
  });

  test("a revoked credential is rejected while others from the same agent still work", async () => {
    const { publicKey, issuer, revocations } = await setup();
    const t1 = await issuer.issue({ agentId: "agent-a", scopes: [], ttlSeconds: 60 }, T0);
    const t2 = await issuer.issue({ agentId: "agent-a", scopes: [], ttlSeconds: 60 }, T0);
    const first = await verifyCredential(t1, publicKey, expected, revocations, T0);
    assert.ok(first.ok);
    revocations.revokeCredential(first.claims.jti);
    assert.equal(expectFail(await verifyCredential(t1, publicKey, expected, revocations, T0)).reason, "REVOKED");
    assert.ok((await verifyCredential(t2, publicKey, expected, revocations, T0)).ok);
  });

  test("revoking an agent (kill switch) also blocks credentials issued afterwards", async () => {
    const { publicKey, issuer, revocations } = await setup();
    revocations.revokeAgent("agent-a");
    const token = await issuer.issue({ agentId: "agent-a", scopes: [], ttlSeconds: 60 }, T0);
    const r = expectFail(await verifyCredential(token, publicKey, expected, revocations, T0));
    assert.equal(r.reason, "REVOKED");
    assert.equal(r.verifiedAgentId, "agent-a");
  });
});
