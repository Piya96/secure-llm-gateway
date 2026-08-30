namespace SecureLlmGateway.Domain;

/// <summary>
/// One permanently-stored, independently verifiable record of an
/// authorization decision. <see cref="Signature"/> is an ECDSA (P-256,
/// SHA-256) signature over the canonical encoding of every other field --
/// see <see cref="Core.SignedAuditLog"/>'s doc comment for exactly why
/// ECDSA rather than the Ed25519 the Tier 6 field guide's source paper
/// uses, and for the canonicalization this signs over.
///
/// The point of signing rather than only hash-chaining (Tier 5's
/// <c>AuditTrailStore</c> does the latter) is a different guarantee:
/// anyone holding only <see cref="Core.SignedAuditLog"/>'s public key --
/// a regulator, an external auditor, a second team with no write access
/// to this system at all -- can verify a specific record was really
/// produced by this gateway's private key and has not been altered
/// since, without needing to trust whoever operates the log storage.
/// </summary>
public sealed record SignedAuditRecord(
    long SequenceNumber,
    DateTime TimestampUtc,
    string SessionId,
    string RequestedByUserId,
    string ToolName,
    string Decision,
    string Reason,
    string ModelRationale,
    string SignatureBase64);
