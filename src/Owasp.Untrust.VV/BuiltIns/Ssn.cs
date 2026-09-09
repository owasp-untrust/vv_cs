using System.Diagnostics.CodeAnalysis;
using System.Text.RegularExpressions;
using Owasp.Untrust.VV.Archetypes;
using Owasp.Untrust.ValueDescriptors.Disclosure;

namespace Owasp.Untrust.VV;

/// <summary>
/// A US Social Security Number in AAA-GG-SSSS form. Invalid area, group, and
/// serial ranges are rejected and public rendering is redacted.
/// </summary>
public sealed class SSN 
    : RegexString<SSN, RedactedPii<string>>
    , IRegexStringDefinition
    , IParsable<SSN>
{
    private SSN(string raw, IFormatProvider? provider)
        : base(raw, provider)
    {
    }

    /// <inheritdoc />
    public static Bounds<int> LengthBounds => new(11, 11);

    /// <inheritdoc />
    public static string Pattern =>
        @"^(?!000)(?!666)(?!9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}$";

    /// <inheritdoc />
    public static RegexOptions Options => RegexOptions.CultureInvariant;

    /// <inheritdoc />
    public static string? Format => "ssn";

    /// <inheritdoc />
    public static SSN Parse(string raw, IFormatProvider? provider) => new(raw, provider);

    /// <inheritdoc />
    public static bool TryParse(
        string? raw,
        IFormatProvider? provider,
        [MaybeNullWhen(false)] out SSN result) =>
        TryParseCore(raw, provider, static (value, format) => new SSN(value, format), out result);
}
