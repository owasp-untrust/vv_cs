using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using Owasp.Untrust.VV.Archetypes;
using Owasp.Untrust.ValueDescriptors.Disclosure;

namespace Owasp.Untrust.VV.Core;

/// <summary>
/// Reusable local validation behavior. The library always executes these stages
/// in parse, normalize, validate, and additional-validation order.
/// </summary>
public interface IValidationTraits<TValue, TDisclosure>
    where TValue : notnull
    where TDisclosure : IDisclosurePolicy<TValue>
{
    static abstract bool TryParse(
        string raw,
        IFormatProvider? provider,
        [MaybeNullWhen(false)] out TValue value);

    static abstract TValue Normalize(TValue value);

    static abstract ValidationIssue? ValidateAdditional(TValue normalized);
}

/// <summary>A library-owned archetype check run after normalization.</summary>
public interface IValidationArchetype<TValue>
    where TValue : notnull
{
    static abstract ValidationIssue? ValidateRaw(string raw);

    static abstract TValue Normalize(TValue parsed);

    static abstract ValidationIssue? Validate(TValue normalized);
}

/// <summary>
/// Traits for bounded strings. Declaring this contract selects the library's
/// mandatory length-checking archetype.
/// </summary>
public interface IBoundedStringTraits<TSelf, TDisclosure>
    : IValidationTraits<string, TDisclosure>
    where TSelf : IBoundedStringTraits<TSelf, TDisclosure>
    where TDisclosure : IDisclosurePolicy<string>
{
    static abstract Bounds<int> LengthBounds { get; }
}

/// <summary>
/// Traits for regex-whitelisted strings. The library enforces bounds, a finite
/// timeout, and the complete whitelist expression before additional validation.
/// </summary>
public interface IRegexStringTraits<TSelf, TDisclosure>
    : IBoundedStringTraits<TSelf, TDisclosure>
    where TSelf : IRegexStringTraits<TSelf, TDisclosure>
    where TDisclosure : IDisclosurePolicy<string>
{
    static abstract string Pattern { get; }

    static abstract RegexOptions Options { get; }

    static abstract TimeSpan MatchTimeout { get; }
}

/// <summary>Required policy for human-readable line text.</summary>
public interface ILineTextTraits<TSelf, TDisclosure>
    : IBoundedStringTraits<TSelf, TDisclosure>
    where TSelf : ILineTextTraits<TSelf, TDisclosure>
    where TDisclosure : IDisclosurePolicy<string>
{
    static abstract bool AllowTab { get; }

    static abstract bool AllowOtherSymbols { get; }

    static abstract bool RequirePathSafeText { get; }
}

/// <summary>Human-readable text that can never contain a line break.</summary>
public interface ISingleLineTextTraits<TSelf, TDisclosure>
    : ILineTextTraits<TSelf, TDisclosure>
    where TSelf : ISingleLineTextTraits<TSelf, TDisclosure>
    where TDisclosure : IDisclosurePolicy<string>;

/// <summary>Human-readable text whose line endings are normalized to LF.</summary>
public interface IMultilineTextTraits<TSelf, TDisclosure>
    : ILineTextTraits<TSelf, TDisclosure>
    where TSelf : IMultilineTextTraits<TSelf, TDisclosure>
    where TDisclosure : IDisclosurePolicy<string>;

/// <summary>
/// Traits for ordered values such as numbers and dates. Raw input length and
/// normalized value bounds are both mandatory and library-enforced.
/// </summary>
public interface IBoundedValueTraits<TSelf, TValue, TDisclosure>
    : IValidationTraits<TValue, TDisclosure>
    where TSelf : IBoundedValueTraits<TSelf, TValue, TDisclosure>
    where TValue : notnull, IComparable<TValue>
    where TDisclosure : IDisclosurePolicy<TValue>
{
    static abstract Bounds<int> RawInputLengthBounds { get; }

    static abstract ComparableBounds<TValue> ValueBounds { get; }
}

/// <summary>Optional schema capability describing a wire format.</summary>
public interface IWireFormatTraits
{
    static abstract string Format { get; }
}

/// <summary>Mandatory bounded-string enforcement supplied by the library.</summary>
public readonly struct BoundedStringArchetype<TTraits, TDisclosure> :
    IValidationArchetype<string>
    where TTraits : IBoundedStringTraits<TTraits, TDisclosure>
    where TDisclosure : IDisclosurePolicy<string>
{
    public static ValidationIssue? ValidateRaw(string raw) => ValidateLength(raw);

    public static string Normalize(string parsed) => parsed;

    public static ValidationIssue? Validate(string normalized) =>
        ValidateLength(normalized);

    private static ValidationIssue? ValidateLength(string value) =>
        TTraits.LengthBounds.Contains(value.Length)
            ? null
            : new ValidationIssue(
                "string.length",
                "The string length is outside the allowed range.");
}

/// <summary>Mandatory bounded regex-whitelist enforcement supplied by the library.</summary>
public readonly struct RegexStringArchetype<TTraits, TDisclosure> :
    IValidationArchetype<string>
    where TTraits : IRegexStringTraits<TTraits, TDisclosure>
    where TDisclosure : IDisclosurePolicy<string>
{
    private static readonly Regex Expression = CreateExpression();

    public static ValidationIssue? ValidateRaw(string raw) =>
        BoundedStringArchetype<TTraits, TDisclosure>.ValidateRaw(raw);

    public static string Normalize(string parsed) => parsed;

    public static ValidationIssue? Validate(string normalized)
    {
        ValidationIssue? bounds = BoundedStringArchetype<TTraits, TDisclosure>.Validate(normalized);
        if (bounds is not null)
        {
            return bounds;
        }

        try
        {
            return Expression.IsMatch(normalized)
                ? null
                : new ValidationIssue(
                    "string.pattern",
                    "The string does not match the required whitelist pattern.");
        }
        catch (RegexMatchTimeoutException)
        {
            return new ValidationIssue(
                "string.pattern_timeout",
                "The whitelist-pattern check exceeded its time limit.");
        }
    }

    private static Regex CreateExpression()
    {
        if (TTraits.MatchTimeout == Regex.InfiniteMatchTimeout || TTraits.MatchTimeout <= TimeSpan.Zero)
        {
            throw new InvalidOperationException("A finite positive regex timeout is required.");
        }

        return new Regex(
            TTraits.Pattern,
            TTraits.Options | RegexOptions.CultureInvariant,
            TTraits.MatchTimeout);
    }
}

/// <summary>Mandatory raw-size and normalized-range enforcement for ordered values.</summary>
public readonly struct BoundedValueArchetype<TTraits, TValue, TDisclosure> :
    IValidationArchetype<TValue>
    where TTraits : IBoundedValueTraits<TTraits, TValue, TDisclosure>
    where TValue : notnull, IComparable<TValue>
    where TDisclosure : IDisclosurePolicy<TValue>
{
    public static ValidationIssue? ValidateRaw(string raw) =>
        TTraits.RawInputLengthBounds.Contains(raw.Length)
            ? null
            : new ValidationIssue(
                "value.raw_length",
                "The input length is outside the allowed range.");

    public static TValue Normalize(TValue parsed) => parsed;

    public static ValidationIssue? Validate(TValue normalized) =>
        TTraits.ValueBounds.Contains(normalized)
            ? null
            : new ValidationIssue(
                "value.bounds",
                "The value is outside the allowed range.");
}

/// <summary>Mandatory Unicode and single-line whitelist enforcement.</summary>
public readonly struct SingleLineTextArchetype<TTraits, TDisclosure> :
    IValidationArchetype<string>
    where TTraits : ISingleLineTextTraits<TTraits, TDisclosure>
    where TDisclosure : IDisclosurePolicy<string>
{
    public static ValidationIssue? ValidateRaw(string raw) =>
        BoundedStringArchetype<TTraits, TDisclosure>.ValidateRaw(raw) ??
        LineTextEnforcement<TTraits, TDisclosure>.ValidateRawUnicode(raw);

    public static string Normalize(string parsed) => parsed.Normalize(NormalizationForm.FormC);

    public static ValidationIssue? Validate(string normalized) =>
        LineTextEnforcement<TTraits, TDisclosure>.Validate(normalized, allowNewlines: false);
}

/// <summary>Mandatory Unicode and multiline whitelist enforcement.</summary>
public readonly struct MultilineTextArchetype<TTraits, TDisclosure> :
    IValidationArchetype<string>
    where TTraits : IMultilineTextTraits<TTraits, TDisclosure>
    where TDisclosure : IDisclosurePolicy<string>
{
    public static ValidationIssue? ValidateRaw(string raw) =>
        BoundedStringArchetype<TTraits, TDisclosure>.ValidateRaw(raw) ??
        LineTextEnforcement<TTraits, TDisclosure>.ValidateRawUnicode(raw);

    public static string Normalize(string parsed) =>
        parsed.Replace("\r\n", "\n", StringComparison.Ordinal)
            .Replace('\r', '\n')
            .Normalize(NormalizationForm.FormC);

    public static ValidationIssue? Validate(string normalized) =>
        LineTextEnforcement<TTraits, TDisclosure>.Validate(normalized, allowNewlines: true);
}

internal static class LineTextEnforcement<TTraits, TDisclosure>
    where TTraits : ILineTextTraits<TTraits, TDisclosure>
    where TDisclosure : IDisclosurePolicy<string>
{
    internal static ValidationIssue? ValidateRawUnicode(string raw) =>
        IsWellFormedUtf16(raw)
            ? null
            : new ValidationIssue("text.unicode", "The text is not well-formed Unicode.");

    internal static ValidationIssue? Validate(string normalized, bool allowNewlines)
    {
        ValidationIssue? bounds = BoundedStringArchetype<TTraits, TDisclosure>.Validate(normalized);
        if (bounds is not null)
        {
            return bounds;
        }

        if (!IsWellFormedUtf16(normalized))
        {
            return new ValidationIssue("text.unicode", "The text is not well-formed Unicode.");
        }

        TextElementEnumerator elements = StringInfo.GetTextElementEnumerator(normalized);
        while (elements.MoveNext())
        {
            if (!IsAllowedElement(elements.GetTextElement(), allowNewlines))
            {
                return new ValidationIssue(
                    "text.characters",
                    "The text contains a character or text element outside the whitelist.");
            }
        }

        if (TTraits.RequirePathSafeText && !IsPathSafe(normalized))
        {
            return new ValidationIssue("text.path", "The text is not safe for use as a path component.");
        }

        return null;
    }

    private static bool IsAllowedElement(string element, bool allowNewlines)
    {
        bool hasBase = false;
        foreach (Rune rune in element.EnumerateRunes())
        {
            if (rune.Value == ' ' || (allowNewlines && rune.Value == '\n') ||
                (TTraits.AllowTab && rune.Value == '\t'))
            {
                hasBase = true;
                continue;
            }

            UnicodeCategory category = Rune.GetUnicodeCategory(rune);
            if (category is UnicodeCategory.NonSpacingMark or
                UnicodeCategory.SpacingCombiningMark or
                UnicodeCategory.EnclosingMark)
            {
                if (!hasBase)
                {
                    return false;
                }

                continue;
            }

            if (!IsAllowedBaseCategory(category))
            {
                return false;
            }

            hasBase = true;
        }

        return hasBase;
    }

    private static bool IsAllowedBaseCategory(UnicodeCategory category) => category is
        UnicodeCategory.UppercaseLetter or
        UnicodeCategory.LowercaseLetter or
        UnicodeCategory.TitlecaseLetter or
        UnicodeCategory.ModifierLetter or
        UnicodeCategory.OtherLetter or
        UnicodeCategory.DecimalDigitNumber or
        UnicodeCategory.LetterNumber or
        UnicodeCategory.OtherNumber or
        UnicodeCategory.ConnectorPunctuation or
        UnicodeCategory.DashPunctuation or
        UnicodeCategory.OpenPunctuation or
        UnicodeCategory.ClosePunctuation or
        UnicodeCategory.InitialQuotePunctuation or
        UnicodeCategory.FinalQuotePunctuation or
        UnicodeCategory.OtherPunctuation or
        UnicodeCategory.MathSymbol or
        UnicodeCategory.CurrencySymbol ||
        (TTraits.AllowOtherSymbols && category == UnicodeCategory.OtherSymbol);

    private static bool IsWellFormedUtf16(string value)
    {
        ReadOnlySpan<char> remaining = value.AsSpan();
        while (!remaining.IsEmpty)
        {
            OperationStatus status = Rune.DecodeFromUtf16(remaining, out _, out int consumed);
            if (status != OperationStatus.Done)
            {
                return false;
            }

            remaining = remaining[consumed..];
        }

        return true;
    }

    private static bool IsPathSafe(string value)
    {
        if (value.IndexOfAny(['<', '>', ':', '"', '|', '?', '*']) >= 0)
        {
            return false;
        }

        return value.Split(['/', '\\']).All(segment => segment is not "." and not "..");
    }
}

internal static class ValidationTraitsPipeline
{
    internal static TValue Run<TValue, TTraits, TArchetype, TDisclosure>(
        string? raw,
        IFormatProvider? provider)
        where TValue : notnull
        where TDisclosure : IDisclosurePolicy<TValue>
        where TTraits : IValidationTraits<TValue, TDisclosure>
        where TArchetype : IValidationArchetype<TValue>
    {
        string input = ValidationPipeline.RequireRaw(raw);
        ValidationPipeline.RequireNoIssue(TArchetype.ValidateRaw(input));
        ValidationPipeline.Require(
            TTraits.TryParse(input, provider, out TValue? parsed),
            "value.parse",
            "The value could not be parsed.");

        TValue normalized = TArchetype.Normalize(TTraits.Normalize(parsed!));
        ValidationPipeline.RequireNoIssue(TArchetype.Validate(normalized));
        ValidationPipeline.RequireNoIssue(TTraits.ValidateAdditional(normalized));
        return normalized;
    }

    internal static bool TryRun<TValue, TTraits, TArchetype, TDisclosure>(
        string? raw,
        IFormatProvider? provider,
        [MaybeNullWhen(false)] out TValue value)
        where TValue : notnull
        where TDisclosure : IDisclosurePolicy<TValue>
        where TTraits : IValidationTraits<TValue, TDisclosure>
        where TArchetype : IValidationArchetype<TValue>
    {
        try
        {
            value = Run<TValue, TTraits, TArchetype, TDisclosure>(raw, provider);
            return true;
        }
        catch (ValidationException)
        {
            value = default;
            return false;
        }
    }
}
