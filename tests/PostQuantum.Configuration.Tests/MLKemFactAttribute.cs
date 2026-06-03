using System.Security.Cryptography;
using Xunit;

namespace PostQuantum.Configuration.Tests;

/// <summary>
/// A <see cref="FactAttribute"/> that skips itself (with a clear reason) on hosts where ML-KEM is not
/// available, and runs fully where it is — e.g. .NET 10+ with OpenSSL 3.5+ on Linux. Mirrors the
/// "tests skip themselves" discipline used across the PostQuantum.* family for native PQ primitives.
/// </summary>
public sealed class MLKemFactAttribute : FactAttribute
{
    public MLKemFactAttribute()
    {
        if (!MLKem.IsSupported)
        {
            Skip = "ML-KEM is not available on this host (needs .NET 10+ and, on Linux, OpenSSL 3.5+).";
        }
    }
}
