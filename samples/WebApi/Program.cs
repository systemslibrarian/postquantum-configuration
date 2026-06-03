// PostQuantum.Configuration — production-shaped ASP.NET Core sample
//
// Demonstrates the real-world shape:
//   * encrypted (pqc.v1) tokens live in appsettings.json, committed to source control;
//   * a key provider is wired through DI (here local; in production a persisted keyring or cloud KMS);
//   * the configuration pipeline decrypts those tokens transparently, so handlers read plaintext;
//   * an admin endpoint mints new tokens (the flow ops uses to add a secret).
//
// Run:   dotnet run --project samples/WebApi
// Then:  curl http://localhost:5080/db/ping
//        curl -X POST http://localhost:5080/secrets/protect -H 'content-type: application/json' -d '{"value":"my-new-secret"}'

using Microsoft.Extensions.Configuration.Json;
using PostQuantum.Configuration;
using PostQuantum.KeyManagement;
using PostQuantum.KeyManagement.Local;

var builder = WebApplication.CreateBuilder(args);

// --- Key custody -----------------------------------------------------------------------------------
// The passphrase is the only real secret; it comes from the environment, never source control.
// The salt is NOT secret — it is committed so the dev tokens in appsettings.json reproduce. In
// production prefer AddPostQuantumKeyManagement with a persisted keyring, or a cloud-KMS provider.
string passphrase =
    builder.Configuration["KeyManagement:Passphrase"]
    ?? Environment.GetEnvironmentVariable("PQC_PASSPHRASE")
    ?? "webapi-dev-passphrase-change-me";

byte[] devSalt = Convert.FromBase64String("AQIDBAUGBwgJCgsMDQ4PEA==");
var keyProvider = LocalContentKeyProvider.Create(passphrase, devSalt, LocalKekOptions.LowMemory);
var protector = new PostQuantumConfigProtector(keyProvider);

// --- Configuration pipeline ------------------------------------------------------------------------
// Replace the default appsettings.json source with an encrypted-aware wrapper so any pqc.v1 token is
// decrypted on read. Plaintext values pass through untouched.
builder.Configuration.Sources.Clear();
builder.Configuration
    .AddEncrypted(
        new JsonConfigurationSource { Path = "appsettings.json", Optional = false, ReloadOnChange = true },
        () => protector)
    .AddEnvironmentVariables();

// --- DI --------------------------------------------------------------------------------------------
builder.Services.AddSingleton<IContentKeyProvider>(keyProvider);
builder.Services.AddPostQuantumConfiguration();

var app = builder.Build();

app.MapGet("/", () => Results.Ok(new
{
    service = "PostQuantum.Configuration sample",
    endpoints = new[] { "GET /db/ping", "GET /secrets/external-api-key", "POST /secrets/protect" },
}));

// The connection string in appsettings.json is an encrypted token, but the handler just reads it as a
// plain string — the transparent layer already decrypted it.
app.MapGet("/db/ping", (IConfiguration config) =>
{
    string? connectionString = config.GetConnectionString("Default");
    return Results.Ok(new
    {
        connected = !string.IsNullOrEmpty(connectionString),
        connectionString = Redact(connectionString),
        note = "Read straight from configuration; decryption happened transparently.",
    });
});

app.MapGet("/secrets/external-api-key", (IConfiguration config) =>
{
    string? apiKey = config["Secrets:ExternalApiKey"];
    return Results.Ok(new
    {
        externalApiKey = Redact(apiKey),
        featureFlag = config["Secrets:FeatureFlag"], // plaintext, shown in full
    });
});

// The ops flow for adding a secret: mint a token, paste the result into appsettings.json.
app.MapPost("/secrets/protect", (ProtectRequest request, IConfigurationProtector p) =>
{
    if (string.IsNullOrEmpty(request.Value))
    {
        return Results.BadRequest(new { error = "Provide a non-empty 'value' to protect." });
    }

    return Results.Ok(new { token = p.Protect(request.Value) });
});

app.Run();

static string Redact(string? secret) =>
    string.IsNullOrEmpty(secret)
        ? "<empty>"
        : $"<{secret.Length} chars, starts \"{secret[..Math.Min(8, secret.Length)]}…\">";

internal sealed record ProtectRequest(string? Value);
