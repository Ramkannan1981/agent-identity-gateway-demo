import { createHash } from "node:crypto";

/**
 * Tamper-EVIDENT audit log (not tamper-PROOF).
 *
 * Each entry's hash covers the previous entry's hash, so editing, deleting,
 * inserting or reordering any entry breaks the chain from that point on, and
 * verifyEntries() reports where.
 *
 * Known limits, stated plainly:
 *  - Truncating the END of the log cannot be detected from the log alone
 *    (the remaining prefix is still a valid chain). Detecting it requires
 *    anchoring the head hash somewhere the attacker can't reach -- pass that
 *    value as `expectedHeadHash` to verifyEntries().
 *  - An attacker who can rewrite the whole log AND recompute every hash can
 *    forge a consistent history. The chain proves consistency, not
 *    authorship. Production needs the head anchored externally or entries
 *    signed by a key the log writer doesn't hold.
 *  - `argsDigest` proves which arguments were used without storing them, but
 *    a hash of a low-entropy value (a small amount, a short id) can be
 *    guessed. It is NOT a substitute for redaction.
 */

export type AuditDecision = "ALLOW" | "DENY" | "REQUIRE_APPROVAL" | "EXECUTION_ERROR";

export interface AuditEntry {
  seq: number;
  timestamp: string;
  /** "unverified" unless the credential's signature was cryptographically verified. */
  agentId: string;
  tool: string;
  decision: AuditDecision;
  ruleId: string;
  reason: string;
  argsDigest: string;
  prevHash: string;
  hash: string;
}

export type AuditInput = Omit<AuditEntry, "seq" | "timestamp" | "prevHash" | "hash">;

export const GENESIS_HASH = "0".repeat(64);

/** JSON with sorted keys, so equal values always serialise (and hash) identically. */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value) ?? "null";
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  const obj = value as Record<string, unknown>;
  const parts = Object.keys(obj)
    .sort()
    .filter((k) => obj[k] !== undefined)
    .map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`);
  return `{${parts.join(",")}}`;
}

export function sha256Hex(input: string): string {
  return createHash("sha256").update(input).digest("hex");
}

export function computeEntryHash(entry: Omit<AuditEntry, "hash">): string {
  return sha256Hex(canonicalJson(entry));
}

export type ChainVerification =
  | { valid: true; headHash: string }
  | { valid: false; brokenAtSeq: number; problem: string };

export function verifyEntries(
  entries: readonly AuditEntry[],
  expectedHeadHash?: string
): ChainVerification {
  let prev = GENESIS_HASH;
  for (let i = 0; i < entries.length; i++) {
    const e = entries[i]!;
    if (e.seq !== i) {
      return { valid: false, brokenAtSeq: i, problem: `expected seq ${i}, found ${e.seq}` };
    }
    if (e.prevHash !== prev) {
      return { valid: false, brokenAtSeq: i, problem: "prevHash does not match the previous entry" };
    }
    const { hash, ...rest } = e;
    if (computeEntryHash(rest) !== hash) {
      return { valid: false, brokenAtSeq: i, problem: "entry contents do not match its hash" };
    }
    prev = hash;
  }
  if (expectedHeadHash !== undefined && prev !== expectedHeadHash) {
    return {
      valid: false,
      brokenAtSeq: entries.length,
      problem: "head hash differs from the anchored value (entries truncated or appended)",
    };
  }
  return { valid: true, headHash: prev };
}

export class AuditLog {
  private readonly log: AuditEntry[] = [];

  constructor(private readonly now: () => Date = () => new Date()) {}

  append(input: AuditInput): AuditEntry {
    const prevHash = this.log.length === 0 ? GENESIS_HASH : this.log[this.log.length - 1]!.hash;
    const base = {
      seq: this.log.length,
      timestamp: this.now().toISOString(),
      ...input,
      prevHash,
    };
    const entry: AuditEntry = { ...base, hash: computeEntryHash(base) };
    this.log.push(entry);
    return entry;
  }

  /** A copy, so callers cannot mutate the log through the returned array. */
  entries(): AuditEntry[] {
    return this.log.map((e) => ({ ...e }));
  }

  verify(expectedHeadHash?: string): ChainVerification {
    return verifyEntries(this.log, expectedHeadHash);
  }

  get headHash(): string {
    return this.log.length === 0 ? GENESIS_HASH : this.log[this.log.length - 1]!.hash;
  }
}
