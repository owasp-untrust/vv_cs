using System.ComponentModel.DataAnnotations;
using System.Diagnostics.CodeAnalysis;
using Owasp.Untrust.VV.Core;
using Owasp.Untrust.ValueDescriptors.Disclosure;
using Owasp.Untrust.VV.Core.StringPreprocessing;

namespace Owasp.Untrust.VV;

/// <summary>A locally validated phone number whose public representation is redacted.</summary>
public sealed class Phone :
    ExposableString<Phone, Phone.PhoneTraits, RedactedPii<string>>,
    IValidatedValueWrapperFactory<Phone, string>
{
    private Phone(string validatedValue)
        : base(validatedValue)
    {
    }

    public static Bounds<int> LengthBounds => PhoneTraits.LengthBounds;

    public static string Format => "phone";

    static Phone IValidatedValueWrapperFactory<Phone, string>.CreateValidated(
        PostValidationRawValue<string, Phone> validated) => new(validated.ValueForReadyConstruction);
    /// <summary>Single-line Unicode and data-annotation validation for phone numbers.</summary>
    public sealed class PhoneTraits :
        StringTraits<
            PhoneTraits,
            SingleLineUnicode,
            DataAnnotationAttributeValidator<PhoneAttribute>>,
        ILengthBoundsTraits<PhoneTraits>
    {
        public static Bounds<int> LengthBounds => new(3, 20);
    }
}
