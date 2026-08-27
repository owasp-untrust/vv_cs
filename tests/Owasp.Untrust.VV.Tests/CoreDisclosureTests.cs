#pragma warning disable CS1591

using System.Diagnostics.CodeAnalysis;
using Xunit;
using Owasp.Untrust.VV.Archetypes;
using Owasp.Untrust.VV.Core;
using Owasp.Untrust.ValueDescriptors.Disclosure;

namespace Owasp.Untrust.VV.Tests;

public sealed class CoreDisclosureTests
{
    [Fact]
    public void Sensitive_built_ins_render_safe_values_but_keep_explicit_escape_hatch()
    {
        var email = Email.Parse("alice@example.test", null);
        var phone = Phone.Parse("+1 202-555-0187", null);
        var ssn = SSN.Parse("123-45-6789", null);
        var card = CreditCard.Parse("4111111111111111", null);

        Assert.Equal("[sensitive]", email.ToString());
        Assert.Equal("[sensitive]", phone.ToPublicValue());
        Assert.Equal("[sensitive]", ssn.ToPublicString());
        Assert.Equal("************1111", card.ToString());
        Assert.Equal("alice@example.test", email.ExposeUnchecked());
        Assert.Equal("4111111111111111", card.ExposeUnchecked());
    }

    [Fact]
    public void Public_policy_preserves_primitive_public_representation()
    {
        var value = PublicCode.Parse("safe", null);
        IValidatedValue erased = value;

        Assert.Equal("safe", erased.ToPublicValue());
        Assert.Equal("safe", erased.ToPublicString());
        Assert.Equal(typeof(string), erased.ValueType);
    }

    [Fact]
    public void Optional_distinguishes_absent_present_and_invalid()
    {
        Assert.True(Optional<Email>.TryParse(null, null, out var absent));
        Assert.False(absent.HasValue);
        Assert.Throws<InvalidOperationException>(() => absent.NonNull);

        Assert.True(Optional<Email>.TryParse("alice@example.test", null, out var present));
        Assert.True(present.HasValue);
        Assert.Equal("alice@example.test", present.NonNull.ExposeUnchecked());

        Assert.False(Optional<Email>.TryParse("invalid", null, out var invalid));
        Assert.False(invalid.HasValue);
    }

    private sealed class PublicCode
        : BoundedString<PublicCode, Public<string>>,
          IBoundedStringDefinition,
          IParsable<PublicCode>
    {
        private PublicCode(string raw, IFormatProvider? provider)
            : base(raw, provider)
        {
        }

        public static Bounds<int> LengthBounds => new(1, 10);

        public static PublicCode Parse(string raw, IFormatProvider? provider) => new(raw, provider);

        public static bool TryParse(
            string? raw,
            IFormatProvider? provider,
            [MaybeNullWhen(false)] out PublicCode result) =>
            TryParseCore(raw, provider, static (value, format) => new PublicCode(value, format), out result);
    }
}
