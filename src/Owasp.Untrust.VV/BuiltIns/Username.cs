using System;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Text.RegularExpressions;
using Owasp.Untrust.ValueDescriptors;
using Owasp.Untrust.ValueDescriptors.Disclosure;
using Owasp.Untrust.VV.Archetypes;
using Owasp.Untrust.VV.Core;

namespace Owasp.Untrust.VV;

/// <summary>
/// Service-provider username. It begins with an ASCII letter and subsequently
/// permits ASCII letters, digits, and underscores.
/// </summary>
public sealed class Username
    : RegexString<Username, RedactedPii<string>>,
        IRegexStringDefinition,
        IParsable<Username>
{
    private Username(string raw, IFormatProvider? provider) : base(raw, provider) { }

    public static Bounds<int> LengthBounds => new(1, 128);
    public static string Pattern => "[A-Za-z][A-Za-z0-9_]*";
    public static RegexOptions Options => RegexOptions.CultureInvariant;
    public static TimeSpan MatchTimeout => TimeSpan.FromMilliseconds(100);
    public static string? Format => null;
    public static string Normalize(string value) => value;
    public static ValidationIssue? ValidateAdditional(string value) => null;

    public static Username Parse(string raw, IFormatProvider? provider) => new(raw, provider);

    public static bool TryParse(
        string? raw,
        IFormatProvider? provider,
        [MaybeNullWhen(false)] out Username result) =>
        TryParseCore(raw, provider, static (value, format) => new Username(value, format), out result);
}
