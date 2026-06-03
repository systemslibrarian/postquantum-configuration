using PostQuantum.Configuration.Tool;
using Xunit;

namespace PostQuantum.Configuration.Tests;

/// <summary>
/// Covers the hand-rolled <c>pqc-config</c> argument parser, in particular the <c>--key=value</c> form
/// that lets a value begin with '-' (otherwise it is mistaken for the next option).
/// </summary>
public sealed class ArgMapTests
{
    private static ArgMap Parse(params string[] args) => ArgMap.Parse(args.AsSpan());

    [Fact]
    public void Space_separated_value_binds_to_its_key()
    {
        ArgMap map = Parse("--keyring", "ring.txt", "--value", "hello");

        Assert.Equal("ring.txt", map.Get("keyring"));
        Assert.Equal("hello", map.Get("value"));
    }

    [Fact]
    public void Inline_equals_form_carries_a_value_that_starts_with_dashes()
    {
        // The whole point of the fix: a secret like "--my-secret" can be passed unambiguously.
        ArgMap map = Parse("--keyring=ring.txt", "--value=--my-secret-key");

        Assert.Equal("ring.txt", map.Get("keyring"));
        Assert.Equal("--my-secret-key", map.Get("value"));
    }

    [Fact]
    public void Inline_equals_keeps_everything_after_the_first_equals()
    {
        ArgMap map = Parse("--value=a=b=c");

        Assert.Equal("a=b=c", map.Get("value"));
    }

    [Fact]
    public void Inline_equals_with_empty_right_side_is_an_explicit_empty_value()
    {
        ArgMap map = Parse("--value=");

        Assert.Equal(string.Empty, map.Get("value"));
    }

    [Fact]
    public void A_trailing_flag_with_no_value_is_a_bare_flag()
    {
        ArgMap map = Parse("--keyring", "ring.txt", "--force");

        Assert.Null(map.Get("force"));
    }

    [Fact]
    public void Space_separated_form_cannot_carry_a_dash_value_so_the_equals_form_is_required()
    {
        // Documents the residual ambiguity: "--value" sees the next token start with "--", so it becomes
        // a bare flag (null) and "--my-secret-key" is parsed as its own flag. Users must use --value=…
        // instead — which is exactly what Inline_equals_form_carries_a_value_that_starts_with_dashes covers.
        ArgMap map = Parse("--value", "--my-secret-key");

        Assert.Null(map.Get("value"));
    }

    [Fact]
    public void A_non_option_argument_is_rejected()
    {
        CliError ex = Assert.Throws<CliError>(() => Parse("protect-me-please"));
        Assert.Contains("Options must start with '--'", ex.Message);
    }
}
