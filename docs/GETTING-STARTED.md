# Getting started

A practical walkthrough: from “I have a plaintext connection string in `appsettings.json`” to “the repo
only holds ciphertext and my app still works unchanged.”

## 1. Install

```bash
dotnet add package PostQuantum.Configuration --prerelease
```

## 2. Choose where the key comes from

Confidentiality rests on a key-encryption key (KEK). In development you can derive one from a passphrase
locally; in production supply the passphrase from a secret store and persist the keyring so it survives
restarts.

```csharp
builder.Services.AddPostQuantumKeyManagement(o =>
{
    o.Passphrase = builder.Configuration["KeyManagement:Passphrase"]   // env var / secret store
        ?? throw new InvalidOperationException("Missing KeyManagement:Passphrase");
    o.WorkFactor = KekWorkFactor.Interactive;   // bump to Moderate/Sensitive for high-value secrets
    o.KeyringPath = "keyring.bin";              // durable, non-secret
});

builder.Services.AddPostQuantumConfiguration();  // registers IConfigurationProtector
```

> **Never** put the passphrase in a checked-in file. The keyring file (`keyring.bin`) is non-secret —
> it holds salts and Argon2id parameters, not key material — but it must be durable.

## 3. Mint a token for each secret

A protected value is just a string. Mint one however you like — a throwaway console app, an admin
endpoint (see the `WebApi` sample's `/secrets/protect`), or `dotnet run` against a snippet:

```csharp
using var keys = LocalContentKeyProvider.Create(passphrase, LocalKekOptions.Interactive);
var protector = new PostQuantumConfigProtector(keys);
Console.WriteLine(protector.Protect("Host=db;Username=app;Password=s3cr3t"));
// -> pqc.v1.AQAAAJ…
```

## 4. Paste the token into configuration

```jsonc
{
  "ConnectionStrings": {
    // was: "Host=db;Username=app;Password=s3cr3t"
    "Default": "pqc.v1.AQAAAJ…"
  }
}
```

The token is safe to commit. Anyone without the passphrase + keyring sees only ciphertext.

## 5. Decrypt transparently on read

Wrap the source so protected values decrypt automatically:

```csharp
builder.Configuration.Sources.Clear();
builder.Configuration
    .AddEncrypted(
        new JsonConfigurationSource { Path = "appsettings.json", Optional = false, ReloadOnChange = true },
        () => builder.Services.BuildServiceProvider().GetRequiredService<IConfigurationProtector>())
    .AddEnvironmentVariables();
```

> In a host, prefer resolving the protector from your already-built provider, or construct it directly
> from the key provider, rather than building a throwaway service provider as shown above for brevity.

Now your existing code is unchanged:

```csharp
string? cs = app.Configuration.GetConnectionString("Default"); // plaintext, decrypted on read
```

## Migrating an existing app (incremental)

You don't have to convert everything at once — protected and plaintext values coexist.

1. Add the package and register the key provider + protector.
2. Wrap your configuration source(s) with `AddEncrypted`. **Plaintext values pass through untouched**,
   so nothing breaks on day one.
3. One secret at a time: mint a token, replace the plaintext value in `appsettings.json` with it,
   redeploy. `IConfigurationProtector.IsProtected(value)` decides per value, so the rollout is
   value-by-value and reversible.
4. Once a value is encrypted, rotate the leaked plaintext credential at its source (the encryption
   protects the *new* value; the old plaintext is still compromised if it ever shipped).

## Prefer explicit decryption?

If you'd rather not wrap the whole source, decrypt specific values yourself:

```csharp
string? cs = app.Configuration.GetDecrypted("ConnectionStrings:Default", protector);
```

## Rotating keys

```csharp
keys.Rotate("a new passphrase", LocalKekOptions.Interactive);
// Old tokens still open (previous KEKs are retained); new Protect() calls use the new active KEK.
```

To physically re-seal stored values under the new key, `Unprotect` then `Protect` them again. A
bulk-rewrap helper is on the roadmap ([`KNOWN-GAPS.md` §4](../KNOWN-GAPS.md)).

---

*To God be the glory — 1 Corinthians 10:31.*
