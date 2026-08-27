using System.Text.Json;
using System.Globalization;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Http.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Owasp.Untrust.VV.Archetypes;
using Owasp.Untrust.VV.AspNetCore;
using Owasp.Untrust.VV.Core;
using Owasp.Untrust.ValueDescriptors.Disclosure;
using Xunit;

namespace Owasp.Untrust.VV.Tests;

public sealed class GeneratedTraitsTests
{
    [Fact]
    public void GeneratedLeaf_InheritsParsingAndUsesTheTraitsPipeline()
    {
        GeneratedSlug value = GeneratedSlug.Parse("  ABC  ", null);

        Assert.Equal("abc", value.ExposeUnchecked());
        Assert.True(typeof(IParsable<GeneratedSlug>).IsAssignableFrom(typeof(GeneratedSlug)));
        Assert.Equal(new Bounds<int>(2, 8), GeneratedSlug.LengthBounds);
        Assert.Equal("slug", GeneratedSlug.Format);
    }

    [Fact]
    public void GeneratedLeaf_RejectsInvalidNormalizedValues()
    {
        Assert.False(GeneratedSlug.TryParse("        a", null, out _));
        Assert.False(GeneratedSlug.TryParse(" a ", null, out _));
        Assert.False(GeneratedSlug.TryParse("contains space", null, out _));
        Assert.Throws<ValidationException>(() => GeneratedSlug.Parse("!x", null));
    }

    [Fact]
    public void GeneratedLeaf_IsJsonBindableThroughInheritedIParsable()
    {
        ServiceCollection services = new();
        services.AddValidatedValues();
        using ServiceProvider provider = services.BuildServiceProvider();
        JsonSerializerOptions options = provider
            .GetRequiredService<IOptions<JsonOptions>>()
            .Value.SerializerOptions;

        GeneratedSlug? value = JsonSerializer.Deserialize<GeneratedSlug>("\"  ABC  \"", options);

        Assert.NotNull(value);
        Assert.Equal("abc", value.ExposeUnchecked());
    }

    [Fact]
    public void BoundedDateTraits_EnforceRawInputAndParsedValueBounds()
    {
        Assert.False(BusinessDate.TryParse("2024-1-1", null, out _));
        Assert.False(BusinessDate.TryParse("1999-12-31", null, out _));

        BusinessDate accepted = BusinessDate.Parse("2024-08-20", null);

        Assert.Equal(new DateOnly(2024, 8, 20), accepted.ExposeUnchecked());
    }

    [Fact]
    public void RegexTraits_EnforceTheWhitelistInTheLibraryArchetype()
    {
        Assert.True(GeneratedIdentifier.TryParse("abc-123", null, out _));
        Assert.False(GeneratedIdentifier.TryParse("abc_123", null, out _));
        Assert.False(GeneratedIdentifier.TryParse("a", null, out _));
    }

    [Fact]
    public void SingleLineTraits_EnforceUnicodeLineAndAdditionalRestrictions()
    {
        DisplayName normalized = DisplayName.Parse("Cafe\u0301", null);

        Assert.Equal("Café", normalized.ExposeUnchecked());
        Assert.False(DisplayName.TryParse("a\nb", null, out _));
        Assert.False(DisplayName.TryParse("a\0b", null, out _));
        Assert.False(DisplayName.TryParse("a\uE000b", null, out _));
        Assert.False(DisplayName.TryParse("a😀b", null, out _));
        Assert.False(DisplayName.TryParse(" leading", null, out _));
        Assert.False(DisplayName.TryParse("a  b", null, out _));
        Assert.False(DisplayName.TryParse("a/../b", null, out _));
        Assert.False(DisplayName.TryParse("\uD800x", null, out _));
    }

    [Fact]
    public void MultilineTraits_NormalizeLineEndingsAndRetainTheWhitelist()
    {
        GeneratedNotes notes = GeneratedNotes.Parse("first\r\nsecond", null);

        Assert.Equal("first\nsecond", notes.ExposeUnchecked());
        Assert.False(GeneratedNotes.TryParse("first\tsecond", null, out _));
        Assert.False(GeneratedNotes.TryParse("first\0second", null, out _));
    }
}

[ValidatedFromTraits<GeneratedSlugTraits>]
public sealed partial class GeneratedSlug
{
}

public readonly struct GeneratedSlugTraits :
    IBoundedStringTraits<GeneratedSlugTraits, Public<string>>,
    IWireFormatTraits
{
    public static Bounds<int> LengthBounds => new(2, 8);

    public static string Format => "slug";

    public static bool TryParse(string raw, IFormatProvider? provider, out string value)
    {
        value = raw;
        return true;
    }

    public static string Normalize(string value) => value.Trim().ToLowerInvariant();

    public static ValidationIssue? ValidateAdditional(string normalized) =>
        normalized.All(character => character is >= 'a' and <= 'z')
            ? null
            : new ValidationIssue("slug.characters", "The slug contains unsupported characters.");
}

[ValidatedFromTraits<BusinessDateTraits>]
public sealed partial class BusinessDate
{
}

public readonly struct BusinessDateTraits :
    IBoundedValueTraits<BusinessDateTraits, DateOnly, Public<DateOnly>>,
    IWireFormatTraits
{
    public static Bounds<int> RawInputLengthBounds => new(10, 10);

    public static ComparableBounds<DateOnly> ValueBounds =>
        new(new DateOnly(2000, 1, 1), new DateOnly(2100, 12, 31));

    public static string Format => "date";

    public static bool TryParse(
        string raw,
        IFormatProvider? provider,
        out DateOnly value) =>
        DateOnly.TryParseExact(
            raw,
            "yyyy-MM-dd",
            provider ?? CultureInfo.InvariantCulture,
            DateTimeStyles.None,
            out value);

    public static DateOnly Normalize(DateOnly value) => value;

    public static ValidationIssue? ValidateAdditional(DateOnly normalized) => null;
}

[ValidatedFromTraits<GeneratedIdentifierTraits>]
public sealed partial class GeneratedIdentifier
{
}

public readonly struct GeneratedIdentifierTraits :
    IRegexStringTraits<GeneratedIdentifierTraits, Public<string>>
{
    public static Bounds<int> LengthBounds => new(2, 32);

    public static string Pattern => "^[a-z0-9]+(?:-[a-z0-9]+)*$";

    public static RegexOptions Options => RegexOptions.None;

    public static TimeSpan MatchTimeout => TimeSpan.FromMilliseconds(100);

    public static bool TryParse(string raw, IFormatProvider? provider, out string value)
    {
        value = raw;
        return true;
    }

    public static string Normalize(string value) => value.ToLowerInvariant();

    public static ValidationIssue? ValidateAdditional(string normalized) => null;
}

[ValidatedFromTraits<DisplayNameTraits>]
public sealed partial class DisplayName
{
}

public readonly struct DisplayNameTraits :
    ISingleLineTextTraits<DisplayNameTraits, Public<string>>
{
    public static Bounds<int> LengthBounds => new(2, 64);

    public static bool AllowTab => false;

    public static bool AllowOtherSymbols => false;

    public static bool RequirePathSafeText => true;

    public static bool TryParse(string raw, IFormatProvider? provider, out string value)
    {
        value = raw;
        return true;
    }

    public static string Normalize(string value) => value;

    public static ValidationIssue? ValidateAdditional(string normalized) =>
        AllOf<NoLeadingOrTrailingWhitespace, NoRepeatedWhitespace>.Validate(normalized);
}

[ValidatedFromTraits<GeneratedNotesTraits>]
public sealed partial class GeneratedNotes
{
}

public readonly struct GeneratedNotesTraits :
    IMultilineTextTraits<GeneratedNotesTraits, Public<string>>
{
    public static Bounds<int> LengthBounds => new(1, 1_024);

    public static bool AllowTab => false;

    public static bool AllowOtherSymbols => false;

    public static bool RequirePathSafeText => false;

    public static bool TryParse(string raw, IFormatProvider? provider, out string value)
    {
        value = raw;
        return true;
    }

    public static string Normalize(string value) => value;

    public static ValidationIssue? ValidateAdditional(string normalized) => null;
}
