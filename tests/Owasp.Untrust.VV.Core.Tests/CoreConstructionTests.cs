#pragma warning disable CS1591

using System.Diagnostics.CodeAnalysis;
using Xunit;
using System.Reflection;
using Owasp.Untrust.VV.Core;
using Owasp.Untrust.ValueDescriptors.Disclosure;
using Owasp.Untrust.VV.StringPreprocessing;
using Owasp.Untrust.VV.Traits;

namespace Owasp.Untrust.VV.Core.Tests;

public sealed class CoreConstructionTests
{
    [Fact]
    public void Parse_runs_fixed_normalization_and_validation_pipeline()
    {
        NormalizedCode value = NormalizedCode.Parse(" ab ", null);

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
        Assert.False(NormalizedCode.TryParse(null, null, out invalid)); // untrust-null-represents-no-value: The test verifies that an absent raw input cannot produce a validated value.
        Assert.Null(invalid);
    }

    [Fact]
    public void Validated_leaf_has_no_public_construction_or_Value_initializer()
    {
        Assert.Empty(typeof(EmailAddress).GetConstructors(BindingFlags.Instance | BindingFlags.Public));
        Assert.Null(typeof(EmailAddress).GetProperty("Value", BindingFlags.Instance | BindingFlags.Public));
        Assert.Null(typeof(EmailAddress).GetMethod("CreateNonValidated", BindingFlags.Static | BindingFlags.Public));
        Assert.Throws<MissingMethodException>(() => Activator.CreateInstance(typeof(EmailAddress)));
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

        ValidationException exception = Assert.Throws<ValidationException>(
            () => NormalizedCode.Parse(rejectedSecret, null));

        Assert.DoesNotContain(rejectedSecret, exception.ToString(), StringComparison.Ordinal);
        Assert.NotEmpty(exception.Code);
    }

    private sealed class NormalizedCode
        : ExposableString<NormalizedCode, NormalizedCode.NormalizedCodeTraits, Public<string>>,
          IValidatedValueWrapperFactory<NormalizedCode, string>
    {
        private NormalizedCode(string value)
            : base(value)
        {
        }

        static NormalizedCode IValidatedValueWrapperFactory<NormalizedCode, string>.CreateValidated(
            PostValidationRawValue<string, NormalizedCode> validated) => new(validated.ValueForReadyConstruction);

        public sealed class NormalizedCodeTraits
            : StringTraits<NormalizedCodeTraits, NormalizedCodeValidation>,
              ILengthBoundsTraits<NormalizedCodeTraits>
        {
            public static Bounds<int> LengthBounds => new(2, 4);
        }

        public readonly struct NormalizedCodeValidation : ICharactersValidator, IStringNormalizer, IStringValidator
        {
            public string NormalizeBeforeValidation(string raw) => raw.Trim().ToUpperInvariant();

            public ValidationIssue? ValidateCharacters(string value) =>
                value.All(character => character is >= 'A' and <= 'Z')
                    ? null
                    : new ValidationIssue("code.characters", "The code contains unsupported characters.");

            public ValidationIssue? ValidateString(string value) =>
                value == "BAD"
                    ? new ValidationIssue("code.reserved", "The code is reserved.")
                    : null;
        }
    }

    private sealed class Port
        : BoundedNumber<Port, int, Public<int>>
        , IBoundedNumber<int>
        , IValidatedValueWrapperFactory<Port, int>
    {
        private Port(int value) : base(value) { }

        public static Bounds<int> Bounds => new(1, 65535);

        static Port IValidatedValueWrapperFactory<Port, int>.CreateValidated(
            PostValidationRawValue<int, Port> validated) => new(validated.ValueForReadyConstruction);
    }
}
