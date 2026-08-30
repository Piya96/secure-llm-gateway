namespace SecureLlmGateway.Domain;

/// <summary>
/// How exposed a tool's damage potential is if invoked wrongly -- OWASP's
/// LLM06:2025 "Excessive Agency" language, made into an explicit,
/// per-tool, policy-set-ahead-of-time field rather than something judged
/// ad hoc at call time. Set once by a human when the tool is registered
/// (see <see cref="Core.ToolRegistry"/>), never inferred from the
/// request.
/// </summary>
public enum RiskTier
{
    /// <summary>Read-only, or trivially reversible. Auto-executes for any identity holding the required role.</summary>
    Low,

    /// <summary>Writes, but within a bounded, reversible scope (e.g. filing a dispute). Auto-executes for the required role.</summary>
    Medium,

    /// <summary>Hard to reverse, or affects funds/limits/account status directly. ALWAYS escalates to a human, regardless of role -- see OWASP LLM06's "excessive autonomy" mitigation.</summary>
    High,
}

/// <summary>
/// A single tool an agent may propose to call, as registered by the
/// institution ahead of time. <see cref="RequiredRole"/> and
/// <see cref="RiskTier"/> are the entire policy surface
/// <see cref="Core.ToolAuthorizationGate"/> reads -- deliberately small
/// and deliberately not configurable per-request, for the same reason
/// <see cref="AgentIdentity"/> can't be overridden per-request: a policy
/// surface a call can influence is a policy surface an attacker can
/// influence.
/// </summary>
/// <param name="Name">Stable tool name, e.g. "get_balance", "transfer_funds".</param>
/// <param name="RequiredRole">The single role an <see cref="AgentIdentity"/> must hold for this tool to be considered at all.</param>
/// <param name="Tier">Governs whether a role match is sufficient (Low/Medium) or must still escalate to a human (High).</param>
public sealed record ToolDefinition(string Name, string RequiredRole, RiskTier Tier);
