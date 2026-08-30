using SecureLlmGateway.Domain;

namespace SecureLlmGateway.Core;

/// <summary>
/// The pre-action authorization enforcement point -- everything else in
/// this repo exists to feed this class correct inputs or to record its
/// output. Intercepts a proposed tool call BEFORE it executes (there is
/// no code path anywhere in this toolkit that calls a tool without going
/// through here first) and evaluates it against a small, fixed policy:
/// does the REAL identity hold the tool's required role, and does the
/// tool's risk tier permit auto-execution or require a human.
///
/// The single rule this class is built around, stated as plainly as
/// possible: <b><see cref="ToolCallRequest.ModelRationale"/> is never
/// read by <see cref="Evaluate"/>.</b> Not filtered, not pattern-matched
/// against a denylist of suspicious phrases, not given partial weight --
/// completely absent from the decision logic below. This is deliberate
/// and is the toolkit's answer to the Tier 6 field guide's Section 01
/// argument: a model that has ingested an injected instruction claiming
/// "compliance pre-approved this transfer" will produce exactly that
/// text in its rationale, indistinguishable at the string level from a
/// legitimate explanation. The only input this method treats as
/// authoritative is <paramref name="identity"/>, which by construction
/// (see <see cref="AgentIdentity"/>'s doc comment) came from the host's
/// own authentication, never from anything the model produced. See
/// <c>verification/authorization_gate_oracle.py</c> for a property test
/// that fuzzes hundreds of adversarial rationale strings against a
/// fixed, under-privileged identity and confirms none of them ever
/// change the outcome.
/// </summary>
public static class ToolAuthorizationGate
{
    public static ToolCallVerdict Evaluate(AgentIdentity identity, ToolCallRequest request)
    {
        var tool = ToolRegistry.Find(request.ToolName);
        if (tool is null)
        {
            // An unregistered tool name is not "assume low-risk and allow" --
            // it's treated exactly like a role failure: Deny. A model
            // proposing a tool this gateway has never heard of is either a
            // bug or an attempt to reach something outside the declared
            // policy surface entirely, and both cases get the same answer.
            return new ToolCallVerdict(
                AuthorizationDecision.Deny,
                $"Tool '{request.ToolName}' is not in the registry -- unknown tools are denied, never assumed safe.",
                request.ToolName, identity.UserId, request.ModelRationale);
        }

        if (!identity.HasRole(tool.RequiredRole))
        {
            return new ToolCallVerdict(
                AuthorizationDecision.Deny,
                $"Identity '{identity.UserId}' lacks required role '{tool.RequiredRole}' for '{tool.Name}'.",
                request.ToolName, identity.UserId, request.ModelRationale);
        }

        if (tool.Tier == RiskTier.High)
        {
            // Role match is necessary but never sufficient at High tier --
            // OWASP LLM06's "excessive autonomy" mitigation, made literal:
            // a high-impact action always needs a human checkpoint, no
            // matter how well-formed the request or how authoritative the
            // model's own rationale sounds.
            return new ToolCallVerdict(
                AuthorizationDecision.EscalateToHuman,
                $"'{tool.Name}' is RiskTier.High -- requires human approval regardless of role match.",
                request.ToolName, identity.UserId, request.ModelRationale);
        }

        return new ToolCallVerdict(
            AuthorizationDecision.Allow,
            $"Identity '{identity.UserId}' holds required role '{tool.RequiredRole}'; tier {tool.Tier} auto-executes.",
            request.ToolName, identity.UserId, request.ModelRationale);
    }
}
