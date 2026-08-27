#pragma warning disable CS1591

using System.Diagnostics.CodeAnalysis;
using Xunit;
using System.Reflection;
using System.Text.RegularExpressions;
using Owasp.Untrust.VV.Archetypes;
using Owasp.Untrust.VV.Core;
using Owasp.Untrust.ValueDescriptors.Disclosure;

namespace Owasp.Untrust.VV.Tests;

public sealed class CoreConstructionTests
{
    [Fact]
    public void Parse_runs_fixed_normalization_and_validation_pipeline()
    {
        var value = NormalizedCode.Parse(" ab ", null);

        Assert.Equal("AB", value.ExposeUnchecked());
        Assert.Equal("AB", value.ToString());
        Assert.Throws<ValidationException>(() => NormalizedCode.Parse(" abc ", null));
        Assert.Throws<ValidationException>(() => NormalizedCode.Parse(" bad", null));
    }

    [Fact]
    public void TryParse_never_returns_a_partially_initialized_value()
    {
        Assert.False(NormalizedCode.TryParse("1!", null, out var invalid));
        Assert.Null(invalid);
        Assert.False(NormalizedCode.TryParse(null, null, out invalid));
        Assert.Null(invalid);
    }

    [Fact]
    public void Validated_leaf_has_no_public_construction_or_Value_initializer()
    {
        Assert.Empty(typeof(Email).GetConstructors(BindingFlags.Instance | BindingFlags.Public));
        Assert.Null(typeof(Email).GetProperty("Value", BindingFlags.Instance | BindingFlags.Public));
        Assert.Null(typeof(Email).GetMethod("CreateNonValidated", BindingFlags.Static | BindingFlags.Public));
        Assert.Throws<MissingMethodException>(() => Activator.CreateInstance(typeof(Email)));
    }

    [Fact]
    public void Bounded_number_uses_provider_and_inclusive_static_bounds()
    {
        Assert.Equal(443, Port.Parse("443", null).ExposeUnchecked());
        Assert.Equal(1, Port.Parse("1", null).ExposeUnchecked());
        Assert.Equal(65535, Port.Parse("65535", null).ExposeUnchecked());
        Assert.False(Port.TryParse("0", null, out _));
        Assert.False(Port.TryParse("65536", null, out _));
        Assert.False(Port.TryParse("not-a-number", null, out _));
    }

    [Fact]
    public void Validation_exception_never_contains_rejected_input()
    {
        const string rejectedSecret = "top-secret-invalid-value";

        var exception = Assert.Throws<ValidationException>(
            () => NormalizedCode.Parse(rejectedSecret, null));

        Assert.DoesNotContain(rejectedSecret, exception.ToString(), StringComparison.Ordinal);
        Assert.NotEmpty(exception.Code);
    }

    private sealed class NormalizedCode
        : RegexString<NormalizedCode, Public<string>>,
          IRegexStringDefinition,
          IParsable<NormalizedCode>
    {
        private NormalizedCode(string raw, IFormatProvider? provider)
            : base(raw, provider)
        {
        }

        public static Bounds<int> LengthBounds => new(2, 4);

        public static string Pattern => "^[A-Z]+$";

        public static RegexOptions Options => RegexOptions.CultureInvariant;

        public static string Normalize(string raw) => raw.Trim().ToUpperInvariant();

        public static ValidationIssue? ValidateAdditional(string normalized) =>
            normalized == "BAD"
                ? new ValidationIssue("code.reserved", "The code is reserved.")
                : null;

        public static NormalizedCode Parse(string raw, IFormatProvider? provider) => new(raw, provider);

        public static bool TryParse(
            string? raw,
            IFormatProvider? provider,
            [MaybeNullWhen(false)] out NormalizedCode result) =>
            TryParseCore(
                raw,
                provider,
                static (value, format) => new NormalizedCode(value, format),
                out result);
    }

    private sealed class Port
        : BoundedNumber<Port, int, Public<int>>,
          IBoundedNumberDefinition<int>,
          IParsable<Port>
    {
        private Port(string raw, IFormatProvider? provider)
            : base(raw, provider)
        {
        }

        public static Bounds<int> Bounds => new(1, 65535);

        public static Port Parse(string raw, IFormatProvider? provider) => new(raw, provider);

        public static bool TryParse(
            string? raw,
            IFormatProvider? provider,
            [MaybeNullWhen(false)] out Port result) =>
            TryParseCore(raw, provider, static (value, format) => new Port(value, format), out result);
    }
}
