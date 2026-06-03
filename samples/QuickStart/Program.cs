// PostQuantum.Configuration — QuickStart
//
// A self-contained, runnable tour of the library:
//   1. seal a sensitive value into a portable token,
//   2. read it back transparently through Microsoft.Extensions.Configuration,
//   3. watch tampering get rejected,
//   4. rotate the key and confirm old tokens still open.
//
// Run it with:  dotnet run --project samples/QuickStart

using Microsoft.Extensions.Configuration;
using PostQuantum.Configuration;
using PostQuantum.KeyManagement.Local;

const string demoConnectionString =
    "Host=db.internal;Port=5432;Database=orders;Username=app;Password=s3cr3t-do-not-ship";

// 1) Stand up a key provider. In production this is normally registered via
//    AddPostQuantumKeyManagement and backed by a persisted keyring or a cloud KMS.
//    The passphrase must come from a secret store or environment variable — never source control.
string passphrase = Environment.GetEnvironmentVariable("PQC_DEMO_PASSPHRASE")
    ?? "quickstart-dev-passphrase-change-me";

using LocalContentKeyProvider keyProvider =
    LocalContentKeyProvider.Create(passphrase, LocalKekOptions.Interactive);

IConfigurationProtector protector = new PostQuantumConfigProtector(keyProvider);

Console.WriteLine("PostQuantum.Configuration — QuickStart");
Console.WriteLine(new string('=', 48));

// 2) Seal the secret. The token is safe to commit to appsettings.json or a repo.
string token = protector.Protect(demoConnectionString);
Console.WriteLine($"\nProtected token (safe to store):\n  {token}");
Console.WriteLine($"\nIs this a protected token? {IConfigurationProtector.IsProtected(token)}");

// 3) Drop the token into configuration and read it back transparently. Application code asks for
//    a connection string and never sees the ciphertext — the AddEncrypted layer decrypts on read.
IConfiguration configuration = new ConfigurationBuilder()
    .AddEncrypted(
        new Microsoft.Extensions.Configuration.Memory.MemoryConfigurationSource
        {
            InitialData = new Dictionary<string, string?>
            {
                ["ConnectionStrings:Orders"] = token,        // encrypted
                ["Logging:LogLevel:Default"] = "Information", // plaintext, passes through untouched
            },
        },
        protector)
    .Build();

string? recovered = configuration.GetConnectionString("Orders");
Console.WriteLine($"\nDecrypted on read via IConfiguration: {Redact(recovered)}");
Console.WriteLine($"Plaintext value passes through:        {configuration["Logging:LogLevel:Default"]}");
Console.WriteLine($"Roundtrip matches original?            {recovered == demoConnectionString}");

// 4) Tampering is detected. Flip one character of the token and decryption fails closed.
string tampered = token[..^2] + (token[^1] == 'A' ? "B" : "A");
Console.WriteLine($"\nTampered token decrypts? {protector.TryUnprotect(tampered, out _)} (expected: False)");

// 5) Rotate the key-encryption key. New values seal under the new KEK; the token minted before the
//    rotation still opens because the previous KEK stays available for unwrapping.
keyProvider.Rotate("a brand-new passphrase", LocalKekOptions.Interactive);
Console.WriteLine($"\nAfter key rotation, the pre-rotation token still opens? "
    + $"{protector.TryUnprotect(token, out string? afterRotation) && afterRotation == demoConnectionString}");

Console.WriteLine("\nDone. To God be the glory — 1 Corinthians 10:31.");

static string Redact(string? connectionString)
{
    if (string.IsNullOrEmpty(connectionString))
    {
        return "<empty>";
    }

    // Never print a recovered secret in full — show only its shape.
    return $"<{connectionString.Length} chars, starts \"{connectionString[..Math.Min(12, connectionString.Length)]}…\">";
}
