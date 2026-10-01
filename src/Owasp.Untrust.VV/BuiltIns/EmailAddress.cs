using System.ComponentModel.DataAnnotations;
using Owasp.Untrust.ValueDescriptors.Disclosure;
using Owasp.Untrust.VV.Core;
using Owasp.Untrust.VV.Core.StringPreprocessing;

namespace Owasp.Untrust.VV;

/// <summary>A single-line email address whose public representation is redacted.</summary>
public sealed class EmailAddress :
    ExposableString<EmailAddress, EmailAddress.EmailAddressTraits, RedactedPii<string>>,
    IValidatedValueWrapperFactory<EmailAddress, string>
{
    private EmailAddress(string validatedValue)
        : base(validatedValue)
    {
    }

    public static Bounds<int> LengthBounds => EmailAddressTraits.LengthBounds;

    public static string Format => "email";

    static EmailAddress IValidatedValueWrapperFactory<EmailAddress, string>.CreateValidated(
        PostValidationRawValue<string, EmailAddress> validated) => new(validated.ValueForReadyConstruction);

    /// <summary>Single-line Unicode and data-annotation validation for email addresses.</summary>
    public sealed class EmailAddressTraits :
        StringTraits<
            EmailAddressTraits,
            SingleLineUnicode,
            DataAnnotationAttributeValidator<EmailAddressAttribute>>,
        ILengthBoundsTraits<EmailAddressTraits>
    {
        public static Bounds<int> LengthBounds => new(5, 254);
    }
}

