namespace SecureLlmGateway.Domain;

/// <summary>
/// The three, and only three, outcomes an authorization decision can
/// reach. Modeled directly on the Tier 6 field guide's Section 03
/// (Allow / Deny / Escalate), which itself follows the arXiv "Before the
/// Tool Call" paper's decision space.
/// </summary>
public enum AuthorizationDecision
{
    /// <summary>Role present, tier Low or Medium -- executes immediately.</summary>
    Allow,

    /// <summary>Required role absent from the real identity's role set. Never executes.</summary>
    Deny,

    /// <summary>Role present, but tier High -- never auto-executes; a human must approve out-of-band.</summary>
    EscalateToHuman,
}

/// <summary>
/// The full, auditable output of one authorization check: the decision,
/// a human-readable reason naming which rule produced it, and the
/// request's own <see cref="ToolCallRequest.ModelRationale"/> carried
/// through verbatim for the record -- present for a human to read,
/// irrelevant to how <see cref="Reason"/> or <see cref="Decision"/> were
/// computed.
/// </summary>
public sealed record ToolCallVerdict(
    AuthorizationDecision Decision,
    string Reason,
    string ToolName,
    string RequestedByUserId,
    string ModelRationale);
