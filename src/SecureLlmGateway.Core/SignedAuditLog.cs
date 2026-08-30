using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;
using SecureLlmGateway.Domain;

namespace SecureLlmGateway.Core;

/// <summary>
/// Appends a cryptographically signed, permanent record of every
/// <see cref="ToolCallVerdict"/> the gate produces, to a SQLite-backed
/// log.
///
/// Signs with ECDSA (NIST P-256 curve, SHA-256 digest) rather than the
/// Ed25519 the Tier 6 field guide's source paper ("Before the Tool
/// Call") uses. That's a deliberate substitution, not an oversight: this
/// portfolio has no .NET SDK available to verify library behavior
/// against, and .NET's <see cref="System.Security.Cryptography.ECDsa"/>
/// has been a stable, unambiguous part of the base class library since
/// .NET Core 3.0, whereas first-class Ed25519 support in the .NET BCL
/// itself is newer and this repo's author isn't confident enough in
/// exactly which .NET 9 APIs cover it to state a specific one without
/// risking a wrong claim. Both are asymmetric signature schemes serving
/// the identical purpose here -- anyone holding the public key can
/// verify a record's authenticity without trusting whoever operates the
/// log -- so the substitution changes the specific curve, not the
/// architectural property being demonstrated. See
/// <c>verification/signed_audit_log_check.py</c> for a live run of this
/// exact ECDSA P-256/SHA-256 construction using Python's
/// <c>cryptography</c> library, including a genuine tamper-then-fail
/// signature verification.
/// </summary>
public sealed class SignedAuditLog : IDisposable
{
    private readonly string _connectionString;
    private readonly ECDsa _signingKey;

    /// <summary>
    /// Creates a fresh signing key pair for this log instance. In a real
    /// deployment the private key would be held in a key vault / HSM and
    /// injected, never generated ad hoc per process -- this constructor
    /// generating one inline is a demo simplification, called out here
    /// rather than left implicit.
    /// </summary>
    public SignedAuditLog(string dbPath)
    {
        _connectionString = $"Data Source={dbPath}";
        _signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        using var conn = new SqliteConnection(_connectionString);
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS SignedAuditRecords (
                SequenceNumber INTEGER PRIMARY KEY AUTOINCREMENT,
                TimestampUtc TEXT NOT NULL,
                SessionId TEXT NOT NULL,
                RequestedByUserId TEXT NOT NULL,
                ToolName TEXT NOT NULL,
                Decision TEXT NOT NULL,
                Reason TEXT NOT NULL,
                ModelRationale TEXT NOT NULL,
                Signature TEXT NOT NULL
            );
            """;
        cmd.ExecuteNonQuery();
    }

    /// <summary>Base64-encoded SubjectPublicKeyInfo -- what a regulator or external auditor would be handed to verify records independently of this process.</summary>
    public string ExportPublicKeyBase64() => Convert.ToBase64String(_signingKey.ExportSubjectPublicKeyInfo());

    /// <summary>
    /// Canonical, pipe-joined field order that both <see cref="Append"/>
    /// and any external verifier must reproduce exactly to check a
    /// signature -- see <c>verification/signed_audit_log_check.py</c>,
    /// which reconstructs this same string in Python field-for-field.
    /// </summary>
    internal static string Canonicalize(long sequenceNumber, DateTime timestampUtc, string sessionId,
        string requestedByUserId, string toolName, string decision, string reason, string modelRationale)
    {
        return string.Join("|",
            sequenceNumber.ToString(CultureInfo.InvariantCulture),
            timestampUtc.ToString("O", CultureInfo.InvariantCulture),
            sessionId, requestedByUserId, toolName, decision, reason, modelRationale);
    }

    public SignedAuditRecord Append(ToolCallVerdict verdict, string sessionId)
    {
        var timestamp = DateTime.UtcNow;

        using var conn = new SqliteConnection(_connectionString);
        conn.Open();

        // Reserve the sequence number first (SQLite's AUTOINCREMENT),
        // then sign over it -- the signature has to cover the sequence
        // number itself so a record can't be silently renumbered later
        // without invalidating its own signature.
        using var insertPlaceholder = conn.CreateCommand();
        insertPlaceholder.CommandText = """
            INSERT INTO SignedAuditRecords
                (TimestampUtc, SessionId, RequestedByUserId, ToolName, Decision, Reason, ModelRationale, Signature)
            VALUES (@ts, @session, @user, @tool, @decision, @reason, @rationale, '');
            SELECT last_insert_rowid();
            """;
        insertPlaceholder.Parameters.AddWithValue("@ts", timestamp.ToString("O", CultureInfo.InvariantCulture));
        insertPlaceholder.Parameters.AddWithValue("@session", sessionId);
        insertPlaceholder.Parameters.AddWithValue("@user", verdict.RequestedByUserId);
        insertPlaceholder.Parameters.AddWithValue("@tool", verdict.ToolName);
        insertPlaceholder.Parameters.AddWithValue("@decision", verdict.Decision.ToString());
        insertPlaceholder.Parameters.AddWithValue("@reason", verdict.Reason);
        insertPlaceholder.Parameters.AddWithValue("@rationale", verdict.ModelRationale);
        long sequenceNumber = Convert.ToInt64(insertPlaceholder.ExecuteScalar());

        string canonical = Canonicalize(sequenceNumber, timestamp, sessionId, verdict.RequestedByUserId,
            verdict.ToolName, verdict.Decision.ToString(), verdict.Reason, verdict.ModelRationale);
        byte[] signature = _signingKey.SignData(Encoding.UTF8.GetBytes(canonical), HashAlgorithmName.SHA256);
        string signatureBase64 = Convert.ToBase64String(signature);

        using var updateSignature = conn.CreateCommand();
        updateSignature.CommandText = "UPDATE SignedAuditRecords SET Signature = @sig WHERE SequenceNumber = @seq";
        updateSignature.Parameters.AddWithValue("@sig", signatureBase64);
        updateSignature.Parameters.AddWithValue("@seq", sequenceNumber);
        updateSignature.ExecuteNonQuery();

        return new SignedAuditRecord(sequenceNumber, timestamp, sessionId, verdict.RequestedByUserId,
            verdict.ToolName, verdict.Decision.ToString(), verdict.Reason, verdict.ModelRationale, signatureBase64);
    }

    /// <summary>
    /// Verifies every stored record's signature against the canonical
    /// encoding of its own stored fields, using this instance's public
    /// key. Returns the sequence number of the first record whose
    /// signature does not verify, or null if every record verifies.
    /// </summary>
    public long? VerifyAll()
    {
        using var conn = new SqliteConnection(_connectionString);
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            SELECT SequenceNumber, TimestampUtc, SessionId, RequestedByUserId, ToolName, Decision, Reason, ModelRationale, Signature
            FROM SignedAuditRecords ORDER BY SequenceNumber ASC
            """;
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            long seq = reader.GetInt64(0);
            var timestamp = DateTime.Parse(reader.GetString(1), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);
            string sessionId = reader.GetString(2);
            string userId = reader.GetString(3);
            string toolName = reader.GetString(4);
            string decision = reader.GetString(5);
            string reason = reader.GetString(6);
            string rationale = reader.GetString(7);
            string signatureBase64 = reader.GetString(8);

            string canonical = Canonicalize(seq, timestamp, sessionId, userId, toolName, decision, reason, rationale);
            bool valid = _signingKey.VerifyData(Encoding.UTF8.GetBytes(canonical),
                Convert.FromBase64String(signatureBase64), HashAlgorithmName.SHA256);
            if (!valid) return seq;
        }
        return null;
    }

    /// <summary>
    /// The independent-auditor path: verifies one record's signature
    /// using ONLY a public key (as exported by
    /// <see cref="ExportPublicKeyBase64"/>), with no access to this
    /// instance, this process, or the private key at all. This is the
    /// concrete demonstration of the doc comment's central claim -- a
    /// regulator handed just the public key and a copy of the database
    /// file can independently confirm a record's authenticity.
    /// </summary>
    public static bool VerifyRecordWithPublicKey(string publicKeyBase64, SignedAuditRecord record)
    {
        using var publicOnlyKey = ECDsa.Create();
        publicOnlyKey.ImportSubjectPublicKeyInfo(Convert.FromBase64String(publicKeyBase64), out _);

        string canonical = Canonicalize(record.SequenceNumber, record.TimestampUtc, record.SessionId,
            record.RequestedByUserId, record.ToolName, record.Decision, record.Reason, record.ModelRationale);
        return publicOnlyKey.VerifyData(Encoding.UTF8.GetBytes(canonical),
            Convert.FromBase64String(record.SignatureBase64), HashAlgorithmName.SHA256);
    }

    public void Dispose() => _signingKey.Dispose();
}
