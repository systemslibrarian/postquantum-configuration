namespace PostQuantum.Configuration;

/// <summary>
/// Thrown when a protected configuration value cannot be produced or recovered: a malformed or
/// truncated token, an unsupported token version, a tampered ciphertext (authentication-tag
/// mismatch), or a context mismatch.
/// </summary>
/// <remarks>
/// The message is deliberately coarse — it states <em>that</em> protection failed, never <em>why</em>
/// at a level that would help an attacker distinguish "wrong key" from "tampered ciphertext" from
/// "wrong context". All of those are unified into a single failure mode so the type is safe to log
/// and safe to surface. The original cryptographic exception, when present, is preserved as
/// <see cref="System.Exception.InnerException"/> for local diagnostics but is never part of the
/// public message.
/// </remarks>
public sealed class ConfigurationProtectionException : Exception
{
    /// <summary>Creates the exception with a human-readable message.</summary>
    public ConfigurationProtectionException(string message)
        : base(message)
    {
    }

    /// <summary>Creates the exception with a message and the underlying cause.</summary>
    public ConfigurationProtectionException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
