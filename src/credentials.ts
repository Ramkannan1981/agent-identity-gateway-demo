import { randomUUID } from "node:crypto";
import { SignJWT, jwtVerify, errors } from "jose";

/**
 * Agent credentials: short-lived, signed, scoped.
 *
 * The central idea of this repo: what an agent is ALLOWED to do is decided
 * by a credential and a policy that live OUTSIDE the model. The model can be
 * confused, manipulated, or prompt-injected into *wanting* to do anything --
 * it still cannot do more than its credential permits.
 *
 * Uses the standard `jose` library rather than hand-rolled crypto. Two
 * choices worth calling out:
 *  - Asymmetric signing (EdDSA / Ed25519): the issuer holds the private key;
 *    the gateway only ever holds the public key, so compromising the gateway
 *    does not let an attacker mint credentials.
 *  - The accepted algorithm is PINNED on verification: never let the token
 *    header choose the algorithm (the classic "alg confusion" attack). This is
 *    defense in depth -- jose also independently rejects "alg: none" and
 *    key/algorithm mismatches, so the tests below would still pass without
 *    the pin. It is kept because a security boundary should not depend on a
 *    library's default behaviour staying the same.
 */

export type SigningKey = Parameters<SignJWT["sign"]>[0];
export type VerifyKey = Parameters<typeof jwtVerify>[1];

const ALGORITHM = "EdDSA";

export interface AgentClaims {
  agentId: string;
  scopes: readonly string[];
  limits: { maxAmount?: number };
  jti: string;
  expiresAt: Date;
}

export interface IssueOptions {
  agentId: string;
  scopes: string[];
  /** Keep this short. Short lifetimes bound the damage of a leaked credential. */
  ttlSeconds: number;
  limits?: { maxAmount?: number };
}

export class CredentialIssuer {
  constructor(
    private readonly privateKey: SigningKey,
    readonly issuer: string,
    readonly audience: string
  ) {}

  async issue(opts: IssueOptions, now: Date = new Date()): Promise<string> {
    return new SignJWT({ scopes: opts.scopes, limits: opts.limits ?? {} })
      .setProtectedHeader({ alg: ALGORITHM })
      .setSubject(opts.agentId)
      .setIssuer(this.issuer)
      .setAudience(this.audience)
      .setJti(randomUUID())
      .setIssuedAt(Math.floor(now.getTime() / 1000))
      .setExpirationTime(Math.floor(now.getTime() / 1000) + opts.ttlSeconds)
      .sign(this.privateKey);
  }
}

/**
 * Revocation. In-memory here; a real deployment needs a shared store (and
 * short credential lifetimes so the list stays small).
 *
 * Two levels: a single credential (by jti), or an agent's kill switch (by
 * agentId) that also covers credentials that haven't been issued yet.
 */
export class RevocationList {
  private readonly credentials = new Set<string>();
  private readonly agents = new Set<string>();

  revokeCredential(jti: string): void {
    this.credentials.add(jti);
  }

  revokeAgent(agentId: string): void {
    this.agents.add(agentId);
  }

  isRevoked(claims: Pick<AgentClaims, "jti" | "agentId">): boolean {
    return this.credentials.has(claims.jti) || this.agents.has(claims.agentId);
  }
}

export type VerifyFailureReason =
  | "EXPIRED"
  | "BAD_SIGNATURE"
  | "INVALID_CLAIMS"
  | "MALFORMED"
  | "REVOKED";

export type VerifyResult =
  | { ok: true; claims: AgentClaims }
  | {
      ok: false;
      reason: VerifyFailureReason;
      detail: string;
      /** Only set when the signature was cryptographically verified, so it is
       * safe to attribute the attempt to this agent in the audit log. */
      verifiedAgentId?: string;
    };

export interface ExpectedIdentity {
  issuer: string;
  audience: string;
}

function isStringArray(v: unknown): v is string[] {
  return Array.isArray(v) && v.every((x) => typeof x === "string");
}

export async function verifyCredential(
  token: string,
  publicKey: VerifyKey,
  expected: ExpectedIdentity,
  revocations: RevocationList,
  now: Date = new Date()
): Promise<VerifyResult> {
  let payload;
  try {
    ({ payload } = await jwtVerify(token, publicKey, {
      issuer: expected.issuer,
      audience: expected.audience,
      algorithms: [ALGORITHM], // pinned -- do not trust the token header
      currentDate: now,
      requiredClaims: ["sub", "jti", "exp", "iat"],
    }));
  } catch (e) {
    // JWTExpired extends JWTClaimValidationFailed, so check it first. In both
    // cases jose has already verified the signature before checking claims,
    // which is why it is safe to attribute these to the token's subject.
    if (e instanceof errors.JWTExpired) {
      const sub = e.payload?.sub;
      return {
        ok: false,
        reason: "EXPIRED",
        detail: "credential expired",
        ...(typeof sub === "string" ? { verifiedAgentId: sub } : {}),
      };
    }
    if (e instanceof errors.JWTClaimValidationFailed) {
      return { ok: false, reason: "INVALID_CLAIMS", detail: e.message };
    }
    if (e instanceof errors.JWSSignatureVerificationFailed) {
      return { ok: false, reason: "BAD_SIGNATURE", detail: "signature verification failed" };
    }
    return {
      ok: false,
      reason: "MALFORMED",
      detail: e instanceof Error ? e.constructor.name : "unknown verification error",
    };
  }

  const { sub, jti, exp } = payload;
  const scopes = payload["scopes"];
  const limits = payload["limits"];
  if (
    typeof sub !== "string" ||
    typeof jti !== "string" ||
    typeof exp !== "number" ||
    !isStringArray(scopes) ||
    typeof limits !== "object" ||
    limits === null ||
    Array.isArray(limits)
  ) {
    return {
      ok: false,
      reason: "INVALID_CLAIMS",
      detail: "claims have an unexpected shape",
      ...(typeof sub === "string" ? { verifiedAgentId: sub } : {}),
    };
  }

  const rawMax = (limits as Record<string, unknown>)["maxAmount"];
  const claims: AgentClaims = {
    agentId: sub,
    scopes,
    limits: typeof rawMax === "number" && Number.isFinite(rawMax) ? { maxAmount: rawMax } : {},
    jti,
    expiresAt: new Date(exp * 1000),
  };

  if (revocations.isRevoked(claims)) {
    return { ok: false, reason: "REVOKED", detail: "credential or agent revoked", verifiedAgentId: sub };
  }

  return { ok: true, claims };
}
