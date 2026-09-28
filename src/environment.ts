import { generateKeyPair } from "jose";
import { AuditLog } from "./audit.js";
import { CredentialIssuer, RevocationList } from "./credentials.js";
import { exampleTools } from "./example-tools.js";
import { ToolGateway, type ToolDefinition } from "./gateway.js";

export const ISSUER = "https://issuer.example.test";
export const AUDIENCE = "tool-gateway";

export interface EnvironmentOptions {
  /** Injectable clock, so tests and the demo can move time without sleeping. */
  now?: () => Date;
  tools?: ToolDefinition[];
}

/**
 * Wires up an issuer (holds the private key), a gateway (holds only the
 * public key), a revocation list, and an audit log.
 */
export async function createEnvironment(opts: EnvironmentOptions = {}) {
  const { publicKey, privateKey } = await generateKeyPair("EdDSA");
  const issuer = new CredentialIssuer(privateKey, ISSUER, AUDIENCE);
  const revocations = new RevocationList();
  const audit = new AuditLog(opts.now);
  const gateway = new ToolGateway({
    publicKey,
    expected: { issuer: ISSUER, audience: AUDIENCE },
    revocations,
    audit,
    tools: opts.tools ?? exampleTools,
    ...(opts.now ? { now: opts.now } : {}),
  });
  return { issuer, gateway, revocations, audit, publicKey };
}
