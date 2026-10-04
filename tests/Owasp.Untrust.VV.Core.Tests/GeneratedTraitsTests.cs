using Owasp.Untrust.ValueDescriptors.Disclosure;
using Owasp.Untrust.VV.Core;
using Owasp.Untrust.VV.StringPreprocessing;
using Owasp.Untrust.VV.Traits;
using Xunit;

namespace Owasp.Untrust.VV.Core.Tests;

public sealed class GeneratedTraitsTests
{
    [Fact]
    public void GeneratedStringLeaf_InheritsParsingAndUsesTheTraitsPipeline()
    {
        GeneratedSlug value = GeneratedSlug.Parse("  ABC  ", null);

        Assert.Equal("abc", value.ExposeUnchecked());
        Assert.True(typeof(IParsable<GeneratedSlug>).IsAssignableFrom(typeof(GeneratedSlug)));
        Assert.Equal(new Bounds<int>(2, 8), GeneratedSlug.LengthBounds);
    }

    [Fact]
    public void GeneratedStringLeaf_RejectsInvalidNormalizedValues()
    {
        Assert.False(GeneratedSlug.TryParse(" a ", null, out _));
        Assert.False(GeneratedSlug.TryParse("contains space", null, out _));
        Assert.Throws<ValidationException>(() => GeneratedSlug.Parse("!x", null));
    }

    [Fact]
    public void GeneratedParsableLeaf_UsesTheTraitsPipeline()
    {
        Assert.False(BusinessDate.TryParse("1999-12-31", null, out _));

        BusinessDate accepted = BusinessDate.Parse("2024-08-20", null);

        Assert.Equal(new DateOnly(2024, 8, 20), accepted.ExposeUnchecked());
    }
}

[ValidatedFromTraits<GeneratedSlugTraits, Public<string>>]
internal sealed partial class GeneratedSlug
{
}

internal sealed class GeneratedSlugTraits :
    StringTraits<GeneratedSlugTraits, GeneratedSlugValidation>,
    ILengthBoundsTraits<GeneratedSlugTraits>
{
    public static Bounds<int> LengthBounds => new(2, 8);
}

internal readonly struct GeneratedSlugValidation : ICharactersValidator, IStringNormalizer, IStringValidator
{
    public string NormalizeBeforeValidation(string raw) => raw.Trim().ToLowerInvariant();

    public ValidationIssue? ValidateCharacters(string value) =>
        value.All(character => character is >= 'a' and <= 'z')
            ? null
            : new ValidationIssue("slug.characters", "The slug contains unsupported characters.");

    public ValidationIssue? ValidateString(string value) => null;
}

[ValidatedFromTraits<BusinessDateTraits, Public<DateOnly>>]
internal sealed partial class BusinessDate
{
}

internal readonly struct BusinessDateTraits : IParsableTraits<DateOnly>
{
    public static DateOnly NormalizeValue(DateOnly value) => value;

    public static ValidationIssue? ValidateValue(DateOnly value) =>
        value < new DateOnly(2000, 1, 1) || value > new DateOnly(2100, 12, 31)
            ? new ValidationIssue("business_date.range", "The date is outside the supported range.")
            : null;
}
