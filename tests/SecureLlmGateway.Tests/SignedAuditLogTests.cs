using Microsoft.Data.Sqlite;
using SecureLlmGateway.Core;
using SecureLlmGateway.Domain;
using Xunit;

namespace SecureLlmGateway.Tests;

public class SignedAuditLogTests : IDisposable
{
    private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"signed_audit_test_{Guid.NewGuid():N}.db");

    public void Dispose()
    {
        if (File.Exists(_dbPath)) File.Delete(_dbPath);
    }

    private static ToolCallVerdict SampleVerdict() =>
        new(AuthorizationDecision.Allow, "test reason", "get_balance", "cust-1", "test rationale");

    [Fact]
    public void Append_ProducesAVerifiableSignature()
    {
        using var log = new SignedAuditLog(_dbPath);
        var record = log.Append(SampleVerdict(), "session-1");

        Assert.NotEmpty(record.SignatureBase64);
        Assert.True(SignedAuditLog.VerifyRecordWithPublicKey(log.ExportPublicKeyBase64(), record));
    }

    [Fact]
    public void VerifyAll_PassesOnUntamperedLog()
    {
        using var log = new SignedAuditLog(_dbPath);
        for (int i = 0; i < 5; i++) log.Append(SampleVerdict(), $"session-{i}");

        Assert.Null(log.VerifyAll());
    }

    [Fact]
    public void VerifyAll_DetectsDirectRowMutation()
    {
        using var log = new SignedAuditLog(_dbPath);
        log.Append(SampleVerdict(), "session-1");
        var toTamper = log.Append(SampleVerdict(), "session-2");
        log.Append(SampleVerdict(), "session-3");

        using (var conn = new SqliteConnection($"Data Source={_dbPath}"))
        {
            conn.Open();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "UPDATE SignedAuditRecords SET Decision = 'Deny' WHERE SequenceNumber = @seq";
            cmd.Parameters.AddWithValue("@seq", toTamper.SequenceNumber);
            cmd.ExecuteNonQuery();
        }

        Assert.Equal(toTamper.SequenceNumber, log.VerifyAll());
    }

    [Fact]
    public void VerifyRecordWithPublicKey_FailsForAWrongKey()
    {
        string otherDbPath = Path.Combine(Path.GetTempPath(), $"other_{Guid.NewGuid():N}.db");
        try
        {
            using var log = new SignedAuditLog(_dbPath);
            var record = log.Append(SampleVerdict(), "session-1");

            using var otherLog = new SignedAuditLog(otherDbPath);
            string wrongPublicKey = otherLog.ExportPublicKeyBase64();

            Assert.False(SignedAuditLog.VerifyRecordWithPublicKey(wrongPublicKey, record));
        }
        finally
        {
            if (File.Exists(otherDbPath)) File.Delete(otherDbPath);
        }
    }

    [Fact]
    public void VerifyRecordWithPublicKey_FailsIfAnyFieldIsAlteredInMemory()
    {
        using var log = new SignedAuditLog(_dbPath);
        var record = log.Append(SampleVerdict(), "session-1");
        var tampered = record with { Reason = "a different reason than what was signed" };

        Assert.False(SignedAuditLog.VerifyRecordWithPublicKey(log.ExportPublicKeyBase64(), tampered));
    }
}
