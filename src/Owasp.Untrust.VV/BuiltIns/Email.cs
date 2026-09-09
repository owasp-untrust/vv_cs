using System.ComponentModel.DataAnnotations;
using Owasp.Untrust.VV.Core;
using Owasp.Untrust.ValueDescriptors.Disclosure;

namespace Owasp.Untrust.VV;

/// <summary>A locally validated email address whose public representation is redacted.</summary>
public sealed class Email :
    ValidatedBoundedStringFromTraits<Email, EmailTraits, RedactedPii<string>>,
    IValidatedValueFactory<Email, string>
{
    private Email(string validatedValue)
        : base(validatedValue)
    {
    }

    public static Archetypes.Bounds<int> LengthBounds => EmailTraits.LengthBounds;

    public static string Format => EmailTraits.Format;

    static Email IValidatedValueFactory<Email, string>.CreateValidated(
        InternallyValidatedValue<string, Email> validated) => new(validated.ValueForReadyConstruction);
}

/// <summary>Reusable local validation for email values and email candidates.</summary>
public readonly struct EmailTraits :
    IBoundedStringTraits<EmailTraits, RedactedPii<string>>,
    IWireFormatTraits
{
    private static readonly EmailAddressAttribute Validator = new();

    public static Archetypes.Bounds<int> LengthBounds => new(5, 254);

    public static string Format => "email";

    public static bool TryParse(string raw, IFormatProvider? provider, out string value)
    {
        value = raw;
        return true;
    }

    public static string Normalize(string value) => value;

    public static ValidationIssue? ValidateAdditional(string normalized) =>
        Validator.IsValid(normalized)
            ? null
            : new ValidationIssue("email.format", "The value is not a valid email address.");
}
