using System.Text.RegularExpressions;
using Owasp.Untrust.VV.Core;
using Owasp.Untrust.ValueDescriptors;
using Owasp.Untrust.ValueDescriptors.Disclosure;
using static Owasp.Untrust.ValueDescriptors.RegexAsciiFactory;
using Owasp.Untrust.VV.Core.StringPreprocessing;

namespace Owasp.Untrust.VV;

/// <summary>
/// A US Social Security Number in AAA-GG-SSSS form. Invalid area, group, and
/// serial ranges are rejected and public rendering is redacted.
/// </summary>
public sealed class SSN 
    : ExposableString<SSN, SSN.SsnTraits, RedactedPii<string>>
    , IValidatedValueWrapperFactory<SSN, string>
{
    private SSN(string validatedValue)
        : base(validatedValue)
    {
    }

    /// <inheritdoc />
    public static Bounds<int> LengthBounds => SsnTraits.LengthBounds;

    public static string Format => "ssn";

    static SSN IValidatedValueWrapperFactory<SSN, string>.CreateValidated(
        PostValidationRawValue<string, SSN> validated) => new(validated.ValueForReadyConstruction);
    public sealed class SsnTraits
        : StringTraits<SsnTraits, AsciiRegexValidator<SsnTraits>>,
        ILengthBoundsTraits<SsnTraits>,
        IAsciiRegexPattern<SsnTraits>
    {
        public static RegexAscii Pattern =>
            RegexAscii(@"^(?!000)(?!666)(?!9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}$");

        public static Bounds<int> LengthBounds => new(11, 11);

        public static TimeSpan MatchTimeout => TimeSpan.FromMilliseconds(100);
    }
}
