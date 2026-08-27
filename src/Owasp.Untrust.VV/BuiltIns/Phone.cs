using System.ComponentModel.DataAnnotations;
using System.Diagnostics.CodeAnalysis;
using Owasp.Untrust.VV.Archetypes;
using Owasp.Untrust.VV.Core;
using Owasp.Untrust.ValueDescriptors.Disclosure;

namespace Owasp.Untrust.VV;

/// <summary>A locally validated phone number whose public representation is redacted.</summary>
public sealed class Phone : BoundedString<Phone, RedactedPii<string>>, IBoundedStringDefinition, IParsable<Phone>
{
    private static readonly PhoneAttribute Validator = new();

    private Phone(string raw, IFormatProvider? provider)
        : base(raw, provider)
    {
    }

    /// <inheritdoc />
    public static Bounds<int> LengthBounds => new(3, 20);

    /// <inheritdoc />
    public static string? Format => "phone";

    /// <inheritdoc />
    public static ValidationIssue? ValidateAdditional(string normalized) =>
        Validator.IsValid(normalized)
            ? null
            : new ValidationIssue("phone.format", "The value is not a valid phone number.");

    /// <inheritdoc />
    public static Phone Parse(string raw, IFormatProvider? provider) => new(raw, provider);

    /// <inheritdoc />
    public static bool TryParse(
        string? raw,
        IFormatProvider? provider,
        [MaybeNullWhen(false)] out Phone result) =>
        TryParseCore(raw, provider, static (value, format) => new Phone(value, format), out result);
}
