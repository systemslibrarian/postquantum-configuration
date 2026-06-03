using PostQuantum.Configuration;
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
            return Fail("Could not unprotect: the token is malformed, or the key/context is wrong.");
        }
    }

    private static int Protect(ArgMap options)
    {
        string keyringPath = options.Require("keyring");
        string passphrase = ResolvePassphrase(options);
        string? context = options.Get("context");
        string value = options.Get("value") ?? ReadStdin("value to protect");

        using LocalContentKeyProvider provider = OpenOrCreateKeyring(keyringPath, passphrase);
        var protector = new PostQuantumConfigProtector(provider);
        Console.Out.WriteLine(protector.Protect(value, context));
        return 0;
    }

    private static int Unprotect(ArgMap options)
    {
        string keyringPath = options.Require("keyring");
        string passphrase = ResolvePassphrase(options);
        string? context = options.Get("context");
        string token = options.Get("token") ?? ReadStdin("token to unprotect");

        using LocalContentKeyProvider provider = OpenKeyring(keyringPath, passphrase);
        var protector = new PostQuantumConfigProtector(provider);
        Console.Out.WriteLine(protector.Unprotect(token, context));
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

    // --- keyring helpers ---------------------------------------------------------------------------

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
              protect     Seal a value into a pqc.v1 token (creates the keyring on first use).
              unprotect   Recover the plaintext from a token.
              rotate      Add a fresh active key (same passphrase, new salt); old tokens still open.

            OPTIONS
              --keyring <path>        Path to the keyring file (required).
              --passphrase <value>    KEK passphrase. Prefer the PQC_PASSPHRASE env var instead.
              --value <text>          Value to protect. If omitted, read from stdin.
              --token <text>          Token to unprotect. If omitted, read from stdin.
              --context <text>        Optional context bound into the token (swap resistance).

            Use --option=value (with '=') for any value that starts with '-', e.g.
            --value=--my-secret, otherwise it is mistaken for the next option. Piping the
            value on stdin avoids the issue entirely and keeps it out of your shell history.

            EXAMPLES
              export PQC_PASSPHRASE='a strong passphrase'
              echo 'Host=db;Password=s3cr3t' | pqc-config protect --keyring keyring.txt
              pqc-config unprotect --keyring keyring.txt --token pqc.v1.AQ...
              pqc-config rotate --keyring keyring.txt

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

    internal string Require(string key) =>
        Get(key) ?? throw new CliError($"Missing required option --{key}.");
}
