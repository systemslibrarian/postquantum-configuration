using PostQuantum.Configuration;
using PostQuantum.KeyManagement;
using PostQuantum.KeyManagement.Local;

namespace PostQuantum.Configuration.Tool;

/// <summary>
/// <c>pqc-config</c> — a small CLI to protect / unprotect / rotate encrypted configuration values,
/// backed by a persisted local keyring. Deliberately dependency-light: a hand-rolled argument parser,
/// no external command-line framework.
/// </summary>
internal static class Program
{
    private const string EnvPassphrase = "PQC_PASSPHRASE";

    private static int Main(string[] args)
    {
        try
        {
            if (args.Length == 0 || IsHelp(args[0]))
            {
                PrintUsage();
                return args.Length == 0 ? 1 : 0;
            }

            string command = args[0];
            var options = ArgMap.Parse(args.AsSpan(1));

            return command switch
            {
                "protect" => Protect(options),
                "unprotect" => Unprotect(options),
                "rotate" => Rotate(options),
                "protect-file" => ProtectFile(options),
                "reprotect-file" => ReprotectFile(options),
                "inspect" => Inspect(options),
                "keygen" => Keygen(options),
                _ => Fail($"Unknown command '{command}'. Run 'pqc-config --help'."),
            };
        }
        catch (CliError ex)
        {
            return Fail(ex.Message);
        }
        catch (ConfigurationProtectionException)
        {
            // Opaque on purpose: do not reveal whether it was a wrong passphrase, wrong context, or tamper.
            // The hint is generic advice, not a diagnosis — it names no specific failure mode.
            return Fail(
                "Could not unprotect: the token is malformed, or the key/context is wrong. " +
                "(Values sealed with --bind-key or --context need the same binding to open.)");
        }
        catch (PlatformNotSupportedException ex)
        {
            // ML-KEM is missing on this host — surface the runtime's own actionable message.
            return Fail(ex.Message);
        }
    }

    private static int Protect(ArgMap options)
    {
        string? context = options.Get("context");
        string value = options.Get("value") ?? ReadStdin("value to protect");

        IContentKeyProvider provider = ResolveProvider(options, needUnwrap: false, createKeyring: true);
        using var ownership = provider as IDisposable;
        var protector = new PostQuantumConfigProtector(provider);
        Console.Out.WriteLine(protector.Protect(value, context));
        return 0;
    }

    private static int Unprotect(ArgMap options)
    {
        string? context = options.Get("context");
        string token = options.Get("token") ?? ReadStdin("token to unprotect");

        IContentKeyProvider provider = ResolveProvider(options, needUnwrap: true, createKeyring: false);
        using var ownership = provider as IDisposable;
        var protector = new PostQuantumConfigProtector(provider);
        Console.Out.WriteLine(protector.Unprotect(token, context));
        return 0;
    }

    private static int Keygen(ArgMap options)
    {
        string keyId = HybridKeyFiles.GenerateAndWrite(options.Require("public"), options.Require("private"));

        Console.Out.WriteLine(keyId);
        Console.Error.WriteLine("Generated a hybrid ML-KEM-768 + ECDH P-256 recipient key pair.");
        Console.Error.WriteLine($"  public  ('{HybridKeyFiles.PublicPrefix}…')  — safe to distribute; anyone holding it can seal values.");
        Console.Error.WriteLine($"  private ('{HybridKeyFiles.PrivatePrefix}…')  — SENSITIVE: whoever holds it can decrypt every value");
        Console.Error.WriteLine("  sealed to this recipient. Store it in a secret manager / KMS, never in source control.");
        return 0;
    }

    private static int Rotate(ArgMap options)
    {
        string keyringPath = options.Require("keyring");
        string passphrase = ResolvePassphrase(options);

        using LocalContentKeyProvider provider = OpenKeyring(keyringPath, passphrase);

        // Rotate to a fresh key-encryption key derived from the same passphrase and a new random salt.
        // Previous keys are retained (old tokens still open); new values seal under the new active key.
        // A single-passphrase keyring keeps every key resolvable on the next open — see README.
        string newActiveKeyId = provider.Rotate(passphrase, LocalKekOptions.Interactive);
        File.WriteAllText(keyringPath, provider.ExportMetadata().Encode());

        Console.Error.WriteLine($"Rotated. New active key: {newActiveKeyId}");
        Console.Error.WriteLine("Existing tokens still open under retained keys; re-protect high-value values to migrate them.");
        return 0;
    }

    private static int ProtectFile(ArgMap options)
    {
        string file = options.Require("file");
        var selector = KeySelector.FromOptions(options.Get("keys"), options.Get("section"), options.Has("all"));
        bool bindKey = options.Has("bind-key");
        bool dryRun = options.Has("dry-run");

        var root = JsonConfigFile.Load(file);

        // A dry run needs no keys at all — it only reports what would change.
        IContentKeyProvider? provider = dryRun ? null : ResolveProvider(options, needUnwrap: false, createKeyring: true);
        using var ownership = provider as IDisposable;
        IConfigurationProtector? protector = provider is null ? null : new PostQuantumConfigProtector(provider);

        FileProtectionResult result = FileProtection.Protect(root, protector, selector, bindKey, dryRun);

        if (dryRun)
        {
            foreach (string key in result.ChangedKeys)
            {
                Console.Out.WriteLine(key);
            }

            Console.Error.WriteLine(
                $"Dry run: {result.ChangedKeys.Count} value(s) would be protected " +
                $"({result.AlreadyProtected} already protected). '{file}' was not modified.");
            return 0;
        }

        JsonConfigFile.Save(file, root);
        Console.Error.WriteLine(
            $"Protected {result.ChangedKeys.Count} value(s) in '{file}' " +
            $"({result.AlreadyProtected} already protected, left unchanged).");
        return 0;
    }

    private static int ReprotectFile(ArgMap options)
    {
        string file = options.Require("file");
        bool bindKey = options.Has("bind-key");
        bool dryRun = options.Has("dry-run");
        string? toRecipient = options.Get("to-recipient");

        var root = JsonConfigFile.Load(file);

        // Opening needs the current key (keyring or private recipient key); sealing defaults to the
        // same provider (key rotation), or to --to-recipient for a cross-provider migration — e.g.
        // moving a keyring-sealed file onto hybrid post-quantum wrapping.
        IContentKeyProvider? openerProvider = dryRun ? null : ResolveProvider(options, needUnwrap: true, createKeyring: false);
        using var openerOwnership = openerProvider as IDisposable;
        IContentKeyProvider? sealerProvider = toRecipient is null || dryRun
            ? openerProvider
            : HybridKeyFiles.Load(toRecipient, needUnwrap: false);
        using var sealerOwnership = ReferenceEquals(sealerProvider, openerProvider) ? null : sealerProvider as IDisposable;

        IConfigurationProtector? opener = openerProvider is null ? null : new PostQuantumConfigProtector(openerProvider);
        IConfigurationProtector? sealer = ReferenceEquals(sealerProvider, openerProvider)
            ? opener
            : new PostQuantumConfigProtector(sealerProvider!);

        FileProtectionResult result = FileProtection.Reprotect(root, opener, sealer, bindKey, dryRun);

        if (dryRun)
        {
            foreach (string key in result.ChangedKeys)
            {
                Console.Out.WriteLine(key);
            }

            Console.Error.WriteLine(
                $"Dry run: {result.ChangedKeys.Count} token(s) would be re-sealed. '{file}' was not modified.");
            return 0;
        }

        JsonConfigFile.Save(file, root);
        Console.Error.WriteLine(toRecipient is null
            ? $"Re-sealed {result.ChangedKeys.Count} token(s) in '{file}' under the active key."
            : $"Re-sealed {result.ChangedKeys.Count} token(s) in '{file}' to recipient '{toRecipient}'.");
        return 0;
    }

    private static int Inspect(ArgMap options)
    {
        string token = options.Get("token") ?? ReadStdin("token to inspect");

        if (!ProtectedTokenInfo.TryInspect(token, out ProtectedTokenInfo? info))
        {
            return Fail("Not a well-formed pqc.v1 token.");
        }

        Console.Out.WriteLine($"format version:  {info.FormatVersion}");
        Console.Out.WriteLine($"provider:        {info.ProviderId}");
        Console.Out.WriteLine($"key id:          {info.KeyId}");
        Console.Out.WriteLine($"wrap algorithm:  {info.WrapAlgorithm}");
        Console.Out.WriteLine($"ciphertext:      {info.CiphertextLength} byte(s)");
        Console.Error.WriteLine(
            "Note: well-formed does not mean authentic — only decrypting with the right key proves integrity.");
        return 0;
    }

    // --- key-provider helpers ----------------------------------------------------------------------

    /// <summary>
    /// Resolves the key provider from the mutually exclusive key-source options: <c>--recipient</c>
    /// (a hybrid ML-KEM key file) or <c>--keyring</c> (the passphrase-derived local keyring).
    /// </summary>
    private static IContentKeyProvider ResolveProvider(ArgMap options, bool needUnwrap, bool createKeyring)
    {
        string? recipient = options.Get("recipient");
        if (recipient is not null && options.Has("keyring"))
        {
            throw new CliError("--recipient and --keyring are mutually exclusive; pass one key source.");
        }

        if (recipient is not null)
        {
            return HybridKeyFiles.Load(recipient, needUnwrap);
        }

        string keyringPath = options.Require("keyring");
        string passphrase = ResolvePassphrase(options);
        return createKeyring ? OpenOrCreateKeyring(keyringPath, passphrase) : OpenKeyring(keyringPath, passphrase);
    }

    private static LocalContentKeyProvider OpenOrCreateKeyring(string path, string passphrase)
    {
        if (File.Exists(path))
        {
            return OpenKeyring(path, passphrase);
        }

        LocalContentKeyProvider provider = LocalContentKeyProvider.Create(passphrase, LocalKekOptions.Interactive);
        File.WriteAllText(path, provider.ExportMetadata().Encode());
        Console.Error.WriteLine($"Created new keyring at '{path}'.");
        return provider;
    }

    private static LocalContentKeyProvider OpenKeyring(string path, string passphrase)
    {
        if (!File.Exists(path))
        {
            throw new CliError($"Keyring '{path}' does not exist. Run 'protect' first to create it.");
        }

        LocalKeyringMetadata metadata;
        try
        {
            metadata = LocalKeyringMetadata.Decode(File.ReadAllText(path).Trim());
        }
        catch (Exception ex) when (ex is FormatException or ArgumentException)
        {
            throw new CliError($"Keyring '{path}' is not a valid keyring file.");
        }

        try
        {
            return LocalContentKeyProvider.Import(metadata, _ => passphrase);
        }
        catch (Exception ex) when (ex is InvalidOperationException)
        {
            throw new CliError("Wrong passphrase for this keyring.");
        }
    }

    // --- input helpers -----------------------------------------------------------------------------

    private static string ResolvePassphrase(ArgMap options)
    {
        string? passphrase = options.Get("passphrase") ?? Environment.GetEnvironmentVariable(EnvPassphrase);
        if (string.IsNullOrEmpty(passphrase))
        {
            throw new CliError(
                $"No passphrase. Pass --passphrase <value> or set the {EnvPassphrase} environment variable " +
                "(preferred — it keeps the secret out of your shell history and process list).");
        }

        return passphrase;
    }

    private static string ReadStdin(string what)
    {
        if (!Console.IsInputRedirected)
        {
            throw new CliError($"No {what}. Pass it as an option or pipe it on stdin.");
        }

        string input = Console.In.ReadToEnd();
        // Drop a single trailing newline so `echo secret | pqc-config protect …` works intuitively.
        return input.EndsWith('\n') ? input.TrimEnd('\r', '\n') : input;
    }

    private static bool IsHelp(string arg) => arg is "-h" or "--help" or "help";

    private static int Fail(string message)
    {
        Console.Error.WriteLine($"error: {message}");
        return 1;
    }

    private static void PrintUsage()
    {
        Console.Out.WriteLine(
            """
            pqc-config — encrypt configuration values with PostQuantum.Configuration

            USAGE
              pqc-config <command> [options]

            COMMANDS
              protect         Seal a value into a pqc.v1 token (creates the keyring on first use).
              unprotect       Recover the plaintext from a token.
              rotate          Add a fresh active key (same passphrase, new salt); old tokens still open.
              protect-file    Seal selected string values in a JSON config file, in place (atomic).
              reprotect-file  Re-seal every pqc.v1 token in a JSON config file — onto the active key
                              after a rotate, or onto a hybrid recipient with --to-recipient.
              inspect         Show a token's non-secret metadata (key id, provider) — no keys needed.
              keygen          Generate a hybrid ML-KEM-768 + ECDH P-256 recipient key pair (.NET 10+).

            OPTIONS
              --keyring <path>        Path to the keyring file (required unless --recipient / inspect / --dry-run).
              --recipient <path>      Hybrid key file instead of a keyring (.NET 10+): the public key
                                      seals; decrypting needs the private key file.
              --to-recipient <path>   reprotect-file: re-seal onto this recipient's PUBLIC key —
                                      migrates a keyring-sealed file onto post-quantum hybrid wrapping.
              --public <path>         keygen: where to write the public key file (never overwrites).
              --private <path>        keygen: where to write the PRIVATE key file (never overwrites).
              --passphrase <value>    KEK passphrase. Prefer the PQC_PASSPHRASE env var instead.
              --value <text>          Value to protect. If omitted, read from stdin.
              --token <text>          Token to unprotect/inspect. If omitted, read from stdin.
              --context <text>        Optional context bound into the token (swap resistance).
              --file <path>           JSON file for protect-file / reprotect-file (strict JSON: a
                                      rewrite would destroy comments, so files with comments are rejected).
              --keys <a,b,c>          protect-file: exact keys to seal ('Section:Sub:Name' paths).
                                      A key that is missing or not a string value is an error.
              --section <name>        protect-file: seal every string value under this section.
              --all                   protect-file: seal every string value in the file.
              --bind-key              Bind each value's configuration key as its context
                                      (pairs with AddEncrypted(..., bindKeyAsContext: true)).
              --dry-run               protect-file / reprotect-file: print the keys that would change
                                      (one per line, stdout) and leave the file untouched.

            Use --option=value (with '=') for any value that starts with '-', e.g.
            --value=--my-secret, otherwise it is mistaken for the next option. Piping the
            value on stdin avoids the issue entirely and keeps it out of your shell history.

            EXAMPLES
              export PQC_PASSPHRASE='a strong passphrase'
              echo 'Host=db;Password=s3cr3t' | pqc-config protect --keyring keyring.txt
              pqc-config unprotect --keyring keyring.txt --token pqc.v1.AQ...
              pqc-config protect-file --keyring keyring.txt --file appsettings.json --section ConnectionStrings
              pqc-config rotate --keyring keyring.txt
              pqc-config reprotect-file --keyring keyring.txt --file appsettings.json
              pqc-config inspect --token pqc.v1.AQ...

              # Hybrid post-quantum key wrapping (.NET 10+):
              pqc-config keygen --public recipient.pub --private recipient.key
              pqc-config protect-file --recipient recipient.pub --file appsettings.json --all
              pqc-config unprotect --recipient recipient.key --token pqc.v1.AQ...
              # Migrate a keyring-sealed file onto hybrid ML-KEM wrapping:
              pqc-config reprotect-file --keyring keyring.txt --to-recipient recipient.pub --file appsettings.json

            protect-file and reprotect-file are fail-closed: the whole file is transformed in
            memory and atomically replaced only if every value succeeds — a failure leaves the
            file exactly as it was. Re-running protect-file is harmless (tokens are skipped).

            The keyring file is non-secret (salts + Argon2id parameters, no key material). The
            passphrase is the real secret — never commit it.
            """);
    }
}

/// <summary>A user-facing CLI error whose message is safe to print to stderr.</summary>
internal sealed class CliError(string message) : Exception(message);

/// <summary>Minimal <c>--key value</c> / <c>--flag</c> argument parser.</summary>
internal sealed class ArgMap
{
    private readonly Dictionary<string, string?> _values = new(StringComparer.OrdinalIgnoreCase);

    internal static ArgMap Parse(ReadOnlySpan<string> args)
    {
        var map = new ArgMap();
        for (int i = 0; i < args.Length; i++)
        {
            string arg = args[i];
            if (!arg.StartsWith("--", StringComparison.Ordinal))
            {
                throw new CliError($"Unexpected argument '{arg}'. Options must start with '--'.");
            }

            string body = arg[2..];

            // `--key=value` binds the value inline. This is the unambiguous form and the only way to pass
            // a value that itself starts with '-' (e.g. a secret like `--passw0rd`): the space-separated
            // form below can't tell such a value from the next flag.
            int eq = body.IndexOf('=', StringComparison.Ordinal);
            if (eq >= 0)
            {
                map._values[body[..eq]] = body[(eq + 1)..];
                continue;
            }

            string key = body;
            if (i + 1 < args.Length && !args[i + 1].StartsWith("--", StringComparison.Ordinal))
            {
                map._values[key] = args[++i];
            }
            else
            {
                map._values[key] = null; // bare flag
            }
        }

        return map;
    }

    internal string? Get(string key) => _values.TryGetValue(key, out string? value) ? value : null;

    /// <summary>Returns <see langword="true"/> if the option was supplied at all (bare flag or with a value).</summary>
    internal bool Has(string key) => _values.ContainsKey(key);

    internal string Require(string key) =>
        Get(key) ?? throw new CliError($"Missing required option --{key}.");
}
