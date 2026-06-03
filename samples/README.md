# Samples

Two runnable samples, smallest first.

## `QuickStart` — console, fully self-contained

An end-to-end tour in one file: seal a value, read it back transparently through
`IConfiguration`, watch a tampered token get rejected, and confirm tokens survive a key rotation.
No setup, no committed secrets.

```bash
dotnet run --project samples/QuickStart
```

## `WebApi` — ASP.NET Core, production-shaped

The real-world shape: **encrypted `pqc.v1` tokens live in `appsettings.json`** (committed to source
control), a key provider is wired through DI, and the configuration pipeline decrypts those tokens
transparently so handlers read plaintext. An admin endpoint mints new tokens — the flow ops uses to
add a secret.

```bash
dotnet run --project samples/WebApi
# then, in another terminal:
curl http://localhost:5080/db/ping
curl http://localhost:5080/secrets/external-api-key
curl -X POST http://localhost:5080/secrets/protect \
  -H 'content-type: application/json' -d '{"value":"my-new-secret"}'
```

`/db/ping` reads `ConnectionStrings:Default` — an encrypted token in `appsettings.json` — as an
ordinary string; the value was decrypted on read. Responses redact recovered secrets on purpose.

> The tokens committed in `appsettings.json` were sealed with the **dev** passphrase
> `webapi-dev-passphrase-change-me` and a non-secret salt baked into `Program.cs`, purely so the
> sample runs out of the box. In production the passphrase comes from a secret store or environment
> variable and is never committed; mint tokens with `/secrets/protect` (or an offline CLI) and paste
> the result into your settings.

---

*To God be the glory — 1 Corinthians 10:31.*
