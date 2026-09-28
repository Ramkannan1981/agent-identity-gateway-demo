import type { AgentClaims } from "./credentials.js";

/**
 * Deterministic policy. No model is consulted, so the same credential and the
 * same arguments always produce the same decision -- which is what makes the
 * decision explainable and auditable.
 *
 * Every decision carries a rule id, so an audit reader (or a compliance
 * reviewer) can see *which rule* produced it, not just the outcome.
 *
 * Evaluation order (first match wins):
 *   R1  tool is not registered                       -> DENY  (default deny)
 *   R2  credential lacks the tool's required scope   -> DENY
 *   R3  amount argument missing / not a positive
 *       finite number                                -> DENY  (fail closed)
 *   R4  amount exceeds the credential's own limit,
 *       or the credential has no limit at all        -> DENY
 *   R5  amount is above the tool's approval threshold-> REQUIRE_APPROVAL
 *   R6  otherwise                                    -> ALLOW
 */

export interface ToolPolicy {
  tool: string;
  requiredScope: string;
  /**
   * If set, the tool moves money (or something like it) and this names the
   * argument holding the amount. Enables rules R3-R5.
   */
  amountArg?: string;
  /** Amounts above this need a human, even when within the credential's limit. */
  approvalAbove?: number;
}

export type Effect = "ALLOW" | "DENY" | "REQUIRE_APPROVAL";

export interface PolicyDecision {
  effect: Effect;
  ruleId: string;
  reason: string;
}

export type PolicyMap = ReadonlyMap<string, ToolPolicy>;

export function evaluatePolicy(
  policies: PolicyMap,
  claims: AgentClaims,
  tool: string,
  args: Readonly<Record<string, unknown>>
): PolicyDecision {
  const policy = policies.get(tool);
  if (!policy) {
    return { effect: "DENY", ruleId: "R1-default-deny", reason: `tool "${tool}" is not registered` };
  }

  if (!claims.scopes.includes(policy.requiredScope)) {
    return {
      effect: "DENY",
      ruleId: "R2-missing-scope",
      reason: `credential lacks required scope "${policy.requiredScope}"`,
    };
  }

  if (policy.amountArg !== undefined) {
    const amount = args[policy.amountArg];
    if (typeof amount !== "number" || !Number.isFinite(amount) || amount <= 0) {
      return {
        effect: "DENY",
        ruleId: "R3-invalid-amount",
        reason: `argument "${policy.amountArg}" must be a positive finite number`,
      };
    }

    const limit = claims.limits.maxAmount;
    if (limit === undefined || amount > limit) {
      return {
        effect: "DENY",
        ruleId: "R4-over-credential-limit",
        reason:
          limit === undefined
            ? "credential carries no amount limit, so amount-bearing calls are refused"
            : `amount exceeds this credential's limit`,
      };
    }

    if (policy.approvalAbove !== undefined && amount > policy.approvalAbove) {
      return {
        effect: "REQUIRE_APPROVAL",
        ruleId: "R5-approval-required",
        reason: `amount is above the ${policy.approvalAbove} approval threshold`,
      };
    }
  }

  return { effect: "ALLOW", ruleId: "R6-allow", reason: "all rules satisfied" };
}
