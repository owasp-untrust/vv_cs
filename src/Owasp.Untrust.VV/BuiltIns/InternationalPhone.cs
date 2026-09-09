using System;
using System.Diagnostics.CodeAnalysis;
using System.Text.RegularExpressions;
using Owasp.Untrust.ValueDescriptors.Disclosure;
using Owasp.Untrust.VV.Archetypes;
using Owasp.Untrust.VV.Core;

namespace Owasp.Untrust.VV;

public sealed class InternationalPhone
    : RegexString<InternationalPhone, RedactedPii<string>>,
        IRegexStringDefinition,
        IParsable<InternationalPhone>
{
    private InternationalPhone(string raw, IFormatProvider? provider) : base(raw, provider) { }

    public static Bounds<int> LengthBounds => new(3, 16);
    public static string Pattern => "\\+[1-9][0-9]{1,14}";
    public static RegexOptions Options => RegexOptions.CultureInvariant;
    public static TimeSpan MatchTimeout => TimeSpan.FromMilliseconds(100);
    public static string? Format => null;
    public static string Normalize(string value) => value;
    public static ValidationIssue? ValidateAdditional(string value) => null;

    public static InternationalPhone Parse(string raw, IFormatProvider? provider) => new(raw, provider);

    public static bool TryParse(
        string? raw,
        IFormatProvider? provider,
        [MaybeNullWhen(false)] out InternationalPhone result) =>
        TryParseCore(raw, provider, static (value, format) => new InternationalPhone(value, format), out result);
}
