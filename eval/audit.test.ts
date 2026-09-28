import { describe, test } from "node:test";
import assert from "node:assert/strict";
import { AuditLog, canonicalJson, computeEntryHash, verifyEntries, type AuditEntry } from "../src/audit.js";

const T0 = new Date("2026-01-01T00:00:00Z");

function sampleLog(n = 4): AuditLog {
  let t = T0.getTime();
  const log = new AuditLog(() => new Date((t += 1000)));
  for (let i = 0; i < n; i++) {
    log.append({
      agentId: "agent-a",
      tool: "read_client_record",
      decision: i % 2 === 0 ? "ALLOW" : "DENY",
      ruleId: i % 2 === 0 ? "R6-allow" : "R2-missing-scope",
      reason: `event ${i}`,
      argsDigest: `digest-${i}`,
    });
  }
  return log;
}

describe("audit log: integrity", () => {
  test("an empty log and an untouched log both verify", () => {
    assert.ok(new AuditLog().verify().valid);
    assert.ok(sampleLog().verify().valid);
  });

  test("the head hash reported by the log matches the verified head", () => {
    const log = sampleLog();
    const v = log.verify();
    assert.ok(v.valid);
    assert.equal(v.headHash, log.headHash);
  });

  test("editing a past decision (DENY -> ALLOW) is detected at that entry", () => {
    const entries = sampleLog().entries();
    entries[1]!.decision = "ALLOW";
    const v = verifyEntries(entries);
    assert.equal(v.valid, false);
    if (!v.valid) assert.equal(v.brokenAtSeq, 1);
  });

  test("a smarter attacker who edits an entry AND recomputes its own hash is still caught at the next link", () => {
    const entries = sampleLog().entries();
    const { hash: _stale, ...rest } = { ...entries[1]!, decision: "ALLOW" as const };
    entries[1] = { ...rest, hash: computeEntryHash(rest) }; // entry 1 is now self-consistent
    const v = verifyEntries(entries);
    assert.equal(v.valid, false);
    // Entry 1 verifies on its own, so the break is reported at entry 2, whose
    // prevHash still points at entry 1's ORIGINAL hash.
    if (!v.valid) assert.equal(v.brokenAtSeq, 2);
  });

  test("deleting an entry from the middle is detected", () => {
    const entries = sampleLog().entries();
    entries.splice(1, 1);
    const v = verifyEntries(entries);
    assert.equal(v.valid, false);
    if (!v.valid) assert.equal(v.brokenAtSeq, 1);
  });

  test("reordering entries is detected", () => {
    const entries = sampleLog().entries();
    const tmp = entries[1]!;
    entries[1] = entries[2]!;
    entries[2] = tmp;
    assert.equal(verifyEntries(entries).valid, false);
  });

  test("inserting a forged entry is detected", () => {
    const entries = sampleLog().entries();
    const forged: AuditEntry = { ...entries[1]!, reason: "forged" };
    entries.splice(2, 0, forged);
    assert.equal(verifyEntries(entries).valid, false);
  });

  test("KNOWN LIMIT: truncating the tail is invisible without an anchored head hash", () => {
    const log = sampleLog();
    const anchored = log.headHash;
    const truncated = log.entries().slice(0, 2);
    assert.ok(verifyEntries(truncated).valid, "a prefix is still a valid chain on its own");
    const v = verifyEntries(truncated, anchored);
    assert.equal(v.valid, false, "but it is caught when the head hash was anchored elsewhere");
  });

  test("entries() returns copies: mutating them does not corrupt the real log", () => {
    const log = sampleLog();
    const copy = log.entries();
    copy[0]!.decision = "ALLOW";
    copy.pop();
    assert.ok(log.verify().valid);
    assert.equal(log.entries().length, 4);
  });
});

describe("canonicalJson", () => {
  test("is independent of key order and omits undefined", () => {
    assert.equal(canonicalJson({ b: 1, a: [2, { d: 4, c: 3 }] }), canonicalJson({ a: [2, { c: 3, d: 4 }], b: 1 }));
    assert.equal(canonicalJson({ a: 1, b: undefined }), canonicalJson({ a: 1 }));
  });

  test("distinguishes values that differ", () => {
    assert.notEqual(canonicalJson({ a: 1 }), canonicalJson({ a: "1" }));
    assert.notEqual(canonicalJson([1, 2]), canonicalJson([2, 1]));
  });
});
