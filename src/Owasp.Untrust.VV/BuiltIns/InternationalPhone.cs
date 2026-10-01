using System.Text.RegularExpressions;
using Owasp.Untrust.ValueDescriptors.Disclosure;
using Owasp.Untrust.VV.Core;
using Owasp.Untrust.VV.Core.StringPreprocessing;

namespace Owasp.Untrust.VV;

public sealed class InternationalPhone
    : ExposableString<InternationalPhone, InternationalPhone.InternationalPhoneTraits, RedactedPii<string>>,
        IValidatedValueWrapperFactory<InternationalPhone, string>
{
    private InternationalPhone(string validatedValue) : base(validatedValue) { }

    public static Bounds<int> LengthBounds => InternationalPhoneTraits.LengthBounds;

    static InternationalPhone IValidatedValueWrapperFactory<InternationalPhone, string>.CreateValidated(
        PostValidationRawValue<string, InternationalPhone> validated) => new(validated.ValueForReadyConstruction);
    public sealed class InternationalPhoneTraits
        : StringTraits<
        InternationalPhoneTraits,
        SingleLineUnicode,
        RegexValidator<InternationalPhoneTraits>>,
        ILengthBoundsTraits<InternationalPhoneTraits>,
        IRegexPattern<InternationalPhoneTraits>
    {
        public static Bounds<int> LengthBounds => new(3, 16);
        public static string Pattern => "\\+[1-9][0-9]{1,14}";
        public static RegexOptions Options => RegexOptions.CultureInvariant;
        public static TimeSpan MatchTimeout => TimeSpan.FromMilliseconds(100);
    }
}
