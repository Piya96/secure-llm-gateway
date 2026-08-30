namespace SecureLlmGateway.Domain;

/// <summary>
/// The REAL, authenticated caller behind a tool-call request -- resolved
/// by the host application's own authentication (a JWT, a session cookie,
/// an mTLS client cert; how it's resolved is out of scope for this
/// toolkit) before <see cref="Core.ToolAuthorizationGate"/> ever sees it.
///
/// This is the one piece of state in the entire toolkit that must never
/// be settable from anything the model produces. The field guide's
/// Section 03 argument (arXiv preprint, "Before the Tool Call") is that
/// an LLM agent's authority has to be checked against who is really
/// asking, not who the model's own output claims is asking -- so if you
/// find yourself tempted to add an "OverrideRole" or "AssumedIdentity"
/// property here that a tool call request could set, stop: that's the
/// exact hole this class exists to not have.
/// </summary>
/// <param name="UserId">Stable identifier for the real human (or real service account) behind this session.</param>
/// <param name="Roles">The identity's actual granted roles, as resolved by the host's own IAM/RBAC system -- never inferred from conversation content.</param>
/// <param name="SessionId">The current session's identifier, for correlating a run of decisions in the audit trail.</param>
public sealed record AgentIdentity(string UserId, IReadOnlySet<string> Roles, string SessionId)
{
    public bool HasRole(string role) => Roles.Contains(role);
}
