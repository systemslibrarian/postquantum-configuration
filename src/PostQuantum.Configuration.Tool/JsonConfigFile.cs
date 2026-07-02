using System.Text.Json;
using System.Text.Json.Nodes;

namespace PostQuantum.Configuration.Tool;

/// <summary>
/// Reads, walks, and atomically rewrites a JSON configuration file (an <c>appsettings.json</c>) for the
/// <c>protect-file</c> / <c>reprotect-file</c> commands. String leaves are addressed by their
/// Microsoft.Extensions.Configuration key (<c>Section:Sub:0:Name</c> — colons, array indices as
/// segments), so the keys printed and matched here are exactly the keys application code reads.
/// </summary>
/// <remarks>
/// Fail-closed by construction: the file is parsed strictly (no comments, no trailing commas — a
/// rewrite would silently destroy them), every transformation happens on the in-memory tree, and the
/// result is written to a temporary file that atomically replaces the original. Any failure at any
/// point leaves the original file byte-for-byte untouched.
/// </remarks>
internal static class JsonConfigFile
{
    /// <summary>
    /// Visits one string leaf. Returns the replacement value, or <see langword="null"/> to leave the
    /// leaf unchanged.
    /// </summary>
    internal delegate string? StringLeafVisitor(string configKey, string value);

    /// <summary>Parses <paramref name="path"/> as strict JSON with an object root.</summary>
    /// <exception cref="CliError">The file is missing, not valid strict JSON, or not a JSON object.</exception>
    internal static JsonObject Load(string path)
    {
        if (!File.Exists(path))
        {
            throw new CliError($"File '{path}' does not exist.");
        }

        JsonNode? root;
        try
        {
            root = JsonNode.Parse(File.ReadAllText(path));
        }
        catch (JsonException ex)
        {
            throw new CliError(
                $"'{path}' is not valid strict JSON ({ex.Message}) Note: comments and trailing commas " +
                "are rejected on purpose — rewriting the file would silently destroy them. Remove them first.");
        }

        return root as JsonObject
            ?? throw new CliError($"'{path}' must contain a JSON object at the root.");
    }

    /// <summary>
    /// Serialises <paramref name="root"/> (indented) to a temporary file and atomically replaces
    /// <paramref name="path"/> with it. The original file is untouched unless the replace succeeds.
    /// </summary>
    internal static void Save(string path, JsonObject root)
    {
        string json = root.ToJsonString(new JsonSerializerOptions { WriteIndented = true });
        string temp = path + ".pqc-tmp";
        try
        {
            File.WriteAllText(temp, json + Environment.NewLine);
            File.Move(temp, path, overwrite: true);
        }
        catch
        {
            // Best-effort cleanup; the original file at `path` has not been modified.
            try
            {
                File.Delete(temp);
            }
            catch (IOException)
            {
            }

            throw;
        }
    }

    /// <summary>
    /// Walks every string leaf under <paramref name="root"/> in document order, invoking
    /// <paramref name="visitor"/> with its configuration key, and applies any replacements to the tree.
    /// Non-string leaves (numbers, booleans, nulls) are never visited.
    /// </summary>
    internal static void VisitStringLeaves(JsonObject root, StringLeafVisitor visitor)
    {
        // Stage replacements first: mutating a JsonObject/JsonArray invalidates its enumerator.
        var replacements = new List<(JsonNode Parent, object Accessor, string NewValue)>();
        Collect(root, prefix: null, replacements, visitor);

        foreach ((JsonNode parent, object accessor, string newValue) in replacements)
        {
            if (parent is JsonObject obj)
            {
                obj[(string)accessor] = newValue;
            }
            else
            {
                ((JsonArray)parent)[(int)accessor] = newValue;
            }
        }
    }

    private static void Collect(
        JsonNode node,
        string? prefix,
        List<(JsonNode Parent, object Accessor, string NewValue)> replacements,
        StringLeafVisitor visitor)
    {
        switch (node)
        {
            case JsonObject obj:
                foreach (KeyValuePair<string, JsonNode?> property in obj)
                {
                    Visit(obj, property.Key, property.Value, Combine(prefix, property.Key), replacements, visitor);
                }

                break;

            case JsonArray array:
                for (int i = 0; i < array.Count; i++)
                {
                    Visit(array, i, array[i], Combine(prefix, i.ToString(System.Globalization.CultureInfo.InvariantCulture)), replacements, visitor);
                }

                break;
        }
    }

    private static void Visit(
        JsonNode parent,
        object accessor,
        JsonNode? child,
        string configKey,
        List<(JsonNode Parent, object Accessor, string NewValue)> replacements,
        StringLeafVisitor visitor)
    {
        if (child is JsonValue value && value.TryGetValue(out string? text))
        {
            string? replacement = visitor(configKey, text);
            if (replacement is not null && !ReferenceEquals(replacement, text) && replacement != text)
            {
                replacements.Add((parent, accessor, replacement));
            }
        }
        else if (child is JsonObject or JsonArray)
        {
            Collect(child, configKey, replacements, visitor);
        }
    }

    private static string Combine(string? prefix, string segment) =>
        prefix is null ? segment : prefix + ":" + segment;
}
