using System.Text.RegularExpressions;
using Owasp.Untrust.ValueDescriptors;
using Owasp.Untrust.ValueDescriptors.Disclosure;
using Owasp.Untrust.VV.Core;
using Owasp.Untrust.VV.StringTraitMixins;
using Owasp.Untrust.VV.Traits;

namespace Owasp.Untrust.VV;

/// <summary>
/// Service-provider username. It begins with an ASCII letter and subsequently
/// permits ASCII letters, digits, and underscores.
/// </summary>
public sealed class Username
    : ExposableString<Username, Username.UsernameTraits, RedactedPii<string>>
    , IValidatedValueWrapperFactory<Username, string>
{
    private Username(string validatedValue) : base(validatedValue) { }

    public static Bounds<int> LengthBounds => UsernameTraits.LengthBounds;

    static Username IValidatedValueWrapperFactory<Username, string>.CreateValidated(
        PostValidationRawValue<string, Username> validated) => new(validated.ValueForReadyConstruction);
    public sealed class UsernameTraits
        : StringTraits<UsernameTraits, SingleLineUnicode, RegexValidator<UsernameTraits>>,
        ILengthBoundsTraits<UsernameTraits>,
        IRegexPattern<UsernameTraits>
    {
        public static Bounds<int> LengthBounds => new(1, 128);
        public static string Pattern => "[A-Za-z][A-Za-z0-9_]*";
        public static RegexOptions Options => RegexOptions.CultureInvariant;
        public static TimeSpan MatchTimeout => TimeSpan.FromMilliseconds(100);
    }
}
