using SecureLlmGateway.Domain;

namespace SecureLlmGateway.Core;

/// <summary>
/// A fixed, in-memory catalog of the tools a fictional retail-banking
/// agent may offer to a model, each with the <see cref="RiskTier"/> and
/// <see cref="ToolDefinition.RequiredRole"/> a human decided on ahead of
/// time. Generic retail-banking tool names throughout -- zero
/// employer-specific tools, roles, or naming, matching the rest of this
/// portfolio's rule.
///
/// In a real deployment this would be a database table an institution's
/// own security team maintains, not a hardcoded list -- what matters for
/// this toolkit is the shape (name, required role, risk tier), not the
/// storage mechanism.
/// </summary>
public static class ToolRegistry
{
    public const string RoleCustomer = "Customer";
    public const string RoleBankAgent = "BankAgent";

    private static readonly Dictionary<string, ToolDefinition> Tools = new()
    {
        ["get_balance"] = new ToolDefinition("get_balance", RoleCustomer, RiskTier.Low),
        ["get_transaction_history"] = new ToolDefinition("get_transaction_history", RoleCustomer, RiskTier.Low),
        ["submit_dispute"] = new ToolDefinition("submit_dispute", RoleCustomer, RiskTier.Medium),
        ["transfer_funds"] = new ToolDefinition("transfer_funds", RoleCustomer, RiskTier.High),
        ["reverse_transaction"] = new ToolDefinition("reverse_transaction", RoleBankAgent, RiskTier.High),
        ["close_account"] = new ToolDefinition("close_account", RoleBankAgent, RiskTier.High),
    };

    /// <summary>Returns null for an unregistered tool name -- see <see cref="ToolAuthorizationGate"/> for how that's treated (always Deny, never "assume safe").</summary>
    public static ToolDefinition? Find(string toolName) => Tools.GetValueOrDefault(toolName);

    public static IReadOnlyCollection<ToolDefinition> All => Tools.Values;
}
