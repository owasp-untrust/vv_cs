using Owasp.Untrust.ValueDescriptors;
using Owasp.Untrust.ValueDescriptors.Disclosure;
using Owasp.Untrust.VV.Core;
using Xunit;

namespace Owasp.Untrust.VV.Core.Tests;

public sealed class CoreDisclosureTests
{
    [Fact]
    public void Sensitive_built_ins_render_safe_values_but_keep_explicit_escape_hatch()
    {
        EmailAddress email = EmailAddress.Parse("alice@example.test", null);
        Phone phone = Phone.Parse("+1 202-555-0187", null);
        SSN ssn = SSN.Parse("123-45-6789", null);
        CreditCard card = CreditCard.Parse("4111111111111111", null);

        Assert.Equal("[sensitive]", email.ToString());
        Assert.Equal("[sensitive]", phone.ToPublicString());
        Assert.Equal("[sensitive]", ssn.ToPublicString());
        Assert.Equal("************1111", card.ToString());
        Assert.Equal("alice@example.test", email.ExposeUnchecked());
        Assert.Equal("4111111111111111", card.ExposeUnchecked());
    }

    [Fact]
    public void Public_policy_preserves_primitive_public_representation()
    {
        PublicPort value = PublicPort.Parse("443", null);
        IValidatedValue erased = value;

        Assert.Equal("443", erased.ToPublicString());
        Assert.Equal(typeof(int), erased.ValueType);
        Assert.Null(typeof(IValidatedValue).GetMethod("ToPublicValue"));
    }

    [Fact]
    public void Optional_distinguishes_absent_present_and_invalid()
    {
        Assert.True(Optional<EmailAddress>.TryParse(null, null, out Optional<EmailAddress> absent)); // untrust-null-represents-no-value: The test verifies the optional parser's explicit absent-input state.
        Assert.False(absent.HasValue);
        Assert.Throws<InvalidOperationException>(() => absent.NonNull);

        Assert.True(Optional<EmailAddress>.TryParse("alice@example.test", null, out Optional<EmailAddress> present));
        Assert.True(present.HasValue);
        Assert.Equal("alice@example.test", present.NonNull.ExposeUnchecked());

        Assert.False(Optional<EmailAddress>.TryParse("invalid", null, out _));
    }

    private sealed class PublicPort
        : BoundedNumber<PublicPort, int, Public<int>>,
          IBoundedNumber<int>,
          IValidatedValueWrapperFactory<PublicPort, int>
    {
        private PublicPort(int value) : base(value) { }

        public static Bounds<int> Bounds => new(1, 65_535);

        static PublicPort IValidatedValueWrapperFactory<PublicPort, int>.CreateValidated(
            PostValidationRawValue<int, PublicPort> validated) => new(validated.ValueForReadyConstruction);
    }
}
