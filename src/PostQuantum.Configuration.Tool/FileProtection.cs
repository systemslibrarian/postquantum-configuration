using System.Text.Json.Nodes;

namespace PostQuantum.Configuration.Tool;

/// <summary>
/// Selects which configuration keys a <c>protect-file</c> run seals: an explicit key list
/// (<c>--keys</c>), everything under a section (<c>--section</c>), or every string leaf
/// (<c>--all</c>). Keys compare case-insensitively, matching Microsoft.Extensions.Configuration.
/// </summary>
internal sealed class KeySelector
{
    private readonly HashSet<string>? _keys;
    private readonly HashSet<string>? _unmatched;
    private readonly string? _section;
    private readonly bool _all;

    private KeySelector(HashSet<string>? keys, string? section, bool all)
    {
        _keys = keys;
        _unmatched = keys is null ? null : new HashSet<string>(keys, StringComparer.OrdinalIgnoreCase);
        _section = section;
        _all = all;
    }

    /// <summary>Builds a selector from the mutually exclusive command options.</summary>
    /// <exception cref="CliError">Zero, or more than one, of the three selection options was supplied.</exception>
    internal static KeySelector FromOptions(string? keys, string? section, bool all)
    {
        int supplied = (keys is null ? 0 : 1) + (section is null ? 0 : 1) + (all ? 1 : 0);
        if (supplied != 1)
        {
            throw new CliError("Choose exactly one of --keys <a,b,c>, --section <name>, or --all.");
        }

        if (keys is not null)
        {
            var set = new HashSet<string>(
                keys.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries),
                StringComparer.OrdinalIgnoreCase);
            if (set.Count == 0)
            {
                throw new CliError("--keys was supplied but contains no keys.");
            }

            return new KeySelector(set, section: null, all: false);
        }

        return new KeySelector(keys: null, section, all);
    }

    /// <summary>Returns <see langword="true"/> if <paramref name="configKey"/> is selected.</summary>
    internal bool Matches(string configKey)
    {
        if (_all)
        {
            return true;
        }

        if (_section is not null)
        {
            return configKey.Equals(_section, StringComparison.OrdinalIgnoreCase)
                || configKey.StartsWith(_section + ":", StringComparison.OrdinalIgnoreCase);
        }

        bool matches = _keys!.Contains(configKey);
        if (matches)
        {
            _unmatched!.Remove(configKey);
        }

        return matches;
    }

    /// <summary>
    /// Fails closed if any explicitly requested key never matched a string leaf — a typo'd or
    /// non-string key must be an error, never a silent skip.
    /// </summary>
    /// <exception cref="CliError">At least one requested key was not found as a string value.</exception>
    internal void ThrowIfAnyKeyUnmatched()
    {
        if (_unmatched is { Count: > 0 })
        {
            throw new CliError(
                $"Key(s) not found as string values: {string.Join(", ", _unmatched)}. " +
                "Only string values can be protected; check the key path (segments separated by ':').");
        }
    }
}

/// <summary>The outcome of a <see cref="FileProtection"/> pass over one file.</summary>
/// <param name="ChangedKeys">The configuration keys that were (or, on a dry run, would be) rewritten.</param>
/// <param name="AlreadyProtected">How many selected values were already tokens and were left alone.</param>
internal sealed record FileProtectionResult(IReadOnlyList<string> ChangedKeys, int AlreadyProtected);

/// <summary>The outcome of a keyless <c>audit</c> scan.</summary>
/// <param name="SuspectKeys">Plaintext string leaves that look like they hold a secret.</param>
/// <param name="ProtectedCount">How many values are already protected tokens.</param>
internal sealed record FileAuditResult(IReadOnlyList<string> SuspectKeys, int ProtectedCount);

/// <summary>The outcome of a <c>check</c> verification pass.</summary>
/// <param name="TokensChecked">How many protected tokens were found and test-decrypted.</param>
/// <param name="FailedKeys">Tokens that did not decrypt with the supplied key source.</param>
/// <param name="UnmetRequirements">Required keys that are missing or still plaintext.</param>
internal sealed record FileCheckResult(
    int TokensChecked,
    IReadOnlyList<string> FailedKeys,
    IReadOnlyList<string> UnmetRequirements)
{
    internal bool Passed => FailedKeys.Count == 0 && UnmetRequirements.Count == 0;
}

/// <summary>
/// The in-memory transformations behind <c>protect-file</c> and <c>reprotect-file</c>. Both operate on
/// the parsed tree only — a failure on any value (bad token, wrong key) throws before anything is
/// written, so the file on disk is never partially migrated.
/// </summary>
internal static class FileProtection
{
    /// <summary>
    /// Seals every selected, not-yet-protected string leaf in <paramref name="root"/>. Already-protected
    /// values are counted and skipped, so re-running the command is harmless.
    /// </summary>
    internal static FileProtectionResult Protect(
        JsonObject root,
        IConfigurationProtector? protector,
        KeySelector selector,
        bool bindKeyAsContext,
        bool dryRun)
    {
        var changed = new List<string>();
        int alreadyProtected = 0;

        JsonConfigFile.VisitStringLeaves(root, (key, value) =>
        {
            if (!selector.Matches(key))
            {
                return null;
            }

            if (IConfigurationProtector.IsProtected(value))
            {
                alreadyProtected++;
                return null;
            }

            changed.Add(key);
            return dryRun ? null : protector!.Protect(value, bindKeyAsContext ? key : null);
        });

        selector.ThrowIfAnyKeyUnmatched();
        return new FileProtectionResult(changed, alreadyProtected);
    }

    /// <summary>
    /// Re-seals every protected (<c>pqc.v1.</c>) string leaf in <paramref name="root"/>:
    /// <paramref name="opener"/> decrypts each token and <paramref name="sealer"/> seals it again.
    /// Pass the same protector for both to migrate onto the active key after a rotation; pass
    /// different ones to migrate between key providers (for example, keyring → hybrid recipient).
    /// Plaintext values are never touched, and plaintext is handled via a zeroable <see cref="Secret"/>.
    /// </summary>
    /// <exception cref="ConfigurationProtectionException">
    /// A token is malformed or fails to authenticate — nothing has been written when this throws.
    /// </exception>
    internal static FileProtectionResult Reprotect(
        JsonObject root,
        IConfigurationProtector? opener,
        IConfigurationProtector? sealer,
        bool bindKeyAsContext,
        bool dryRun)
    {
        var changed = new List<string>();

        JsonConfigFile.VisitStringLeaves(root, (key, value) =>
        {
            if (!IConfigurationProtector.IsProtected(value))
            {
                return null;
            }

            changed.Add(key);
            if (dryRun)
            {
                return null;
            }

            string? context = bindKeyAsContext ? key : null;
            using Secret secret = opener!.UnprotectToSecret(value, context);
            return sealer!.Protect(secret.Reveal(), context);
        });

        return new FileProtectionResult(changed, AlreadyProtected: 0);
    }

    // Key-name fragments that usually mean "this value is a secret". Deliberately conservative:
    // a bare "key" would flag every "KeyringPath"-style setting and drown the signal in noise.
    private static readonly string[] SensitiveKeyFragments =
    [
        "password", "passwd", "pwd", "secret", "apikey", "api_key", "api-key",
        "connectionstring", "credential", "privatekey", "private_key", "private-key",
        "accesskey", "access_key", "access-key", "token",
    ];

    /// <summary>
    /// Keyless scan for plaintext values that look like secrets — a value under a sensitive-sounding
    /// key, or a value that embeds a credential (<c>password=</c>) regardless of its key. A heuristic,
    /// stated plainly: it catches the common cases, it cannot prove a file holds no secrets.
    /// </summary>
    internal static FileAuditResult Audit(JsonObject root)
    {
        var suspects = new List<string>();
        int protectedCount = 0;

        JsonConfigFile.VisitStringLeaves(root, (key, value) =>
        {
            if (IConfigurationProtector.IsProtected(value))
            {
                protectedCount++;
                return null;
            }

            if (value.Length == 0)
            {
                return null;
            }

            bool sensitiveKey = SensitiveKeyFragments.Any(f => key.Contains(f, StringComparison.OrdinalIgnoreCase));
            bool embeddedCredential = value.Contains("password=", StringComparison.OrdinalIgnoreCase)
                || value.Contains("pwd=", StringComparison.OrdinalIgnoreCase);
            if (sensitiveKey || embeddedCredential)
            {
                suspects.Add(key);
            }

            return null;
        });

        return new FileAuditResult(suspects, protectedCount);
    }

    /// <summary>
    /// Verifies that every protected token in <paramref name="root"/> decrypts with
    /// <paramref name="protector"/> (a pre-deploy gate: catch a wrong keyring, a missed re-seal, or a
    /// context mismatch in CI, not in production). Plaintext is recovered into a zeroable
    /// <see cref="Secret"/> and discarded — never returned, never printed. Keys listed in
    /// <paramref name="requiredKeys"/> must additionally exist and be protected.
    /// </summary>
    internal static FileCheckResult Check(
        JsonObject root,
        IConfigurationProtector protector,
        bool bindKeyAsContext,
        IReadOnlyCollection<string> requiredKeys)
    {
        var failed = new List<string>();
        var unmetRequirements = new List<string>();
        var protectedKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var plaintextKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        int tokensChecked = 0;

        JsonConfigFile.VisitStringLeaves(root, (key, value) =>
        {
            if (!IConfigurationProtector.IsProtected(value))
            {
                plaintextKeys.Add(key);
                return null;
            }

            protectedKeys.Add(key);
            tokensChecked++;
            try
            {
                using Secret secret = protector.UnprotectToSecret(value, bindKeyAsContext ? key : null);
            }
            catch (ConfigurationProtectionException)
            {
                failed.Add(key);
            }

            return null;
        });

        foreach (string required in requiredKeys)
        {
            if (!protectedKeys.Contains(required))
            {
                unmetRequirements.Add(plaintextKeys.Contains(required)
                    ? $"{required} (present but NOT protected)"
                    : $"{required} (missing)");
            }
        }

        return new FileCheckResult(tokensChecked, failed, unmetRequirements);
    }
}
