namespace SecureLlmGateway.Domain;

/// <summary>
/// What the model proposed: a tool name, its parameters, and the model's
/// own explanation for why it's calling this tool right now.
///
/// <see cref="ModelRationale"/> is the field this entire toolkit is built
/// around NOT trusting. It exists here, and is carried through into
/// every audit record, purely so a human reviewing the trail later can
/// see what the model claimed -- "compliance pre-approved this",
/// "the user's manager authorized an exception", anything an indirect
/// prompt injection (Tier 6 field guide, Section 01) might have talked
/// the model into asserting. <see cref="Core.ToolAuthorizationGate"/>
/// never parses or branches on this string. See
/// <c>verification/authorization_gate_oracle.py</c> for a property test
/// proving that claim -- not just asserting it in a doc comment.
/// </summary>
public sealed record ToolCallRequest(
    string ToolName,
    IReadOnlyDictionary<string, string> Parameters,
    string ModelRationale);
