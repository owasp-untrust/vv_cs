namespace Owasp.Untrust.VV.Core.StringPreprocessing;

/// <summary>
/// Shared implementation for string traits composed from a preprocessing chain.
/// </summary>
/// <remarks>
/// This is deliberately an abstract class rather than a struct or static class.
/// Traits are used only through static generic dispatch, so no instance allocation
/// occurs and a struct would provide no performance benefit. The class hierarchy
/// keeps the required normalization and validation forwarding implementations in
/// one place. A struct cannot inherit that implementation, and a static class can
/// neither inherit it nor implement the static trait contract.
/// </remarks>
public abstract class StringTraitsFixedArgsNum<TSelf, TPreprocessing>
    : IStringTraitsAnonymousPreprocessing<TSelf>
    where TSelf : 
        StringTraitsFixedArgsNum<TSelf, TPreprocessing>,
        IStringTraitsAnonymousPreprocessing<TSelf>,
        ILengthBoundsTraits<TSelf>
    where TPreprocessing : struct, IPreprocessingChain
{
    public static string NormalizeBeforeValidation(string value)
        => TPreprocessing.Normalize(value);

    public static ValidationIssue? ValidateCharacters(string value)
        => TPreprocessing.ValidateCharacters(value);

    public static ValidationIssue? ValidateString(string value)
        => TPreprocessing.ValidateString(value);

    public static ValidationIssue? ValidateValue(string raw, out string normalized)
    {
        Bounds<int> bounds = TSelf.LengthBounds;
        if (!bounds.Contains(raw.Length))
        {
            normalized = raw;
            return new ValidationIssue("string.raw_length", "The raw string length is outside the allowed range.");
        }

        normalized = TSelf.NormalizeBeforeValidation(raw);
        if (!bounds.Contains(normalized.Length))
        {
            return new ValidationIssue("string.length", "The normalized string length is outside the allowed range.");
        }

        Bounds<int> boundsAfterNormalization = TSelf.LengthBounds;
        if (!boundsAfterNormalization.Contains(normalized.Length))
        {
            return new ValidationIssue("string.length", "The normalized string length is outside the allowed range.");
        }

        ValidationIssue? characterIssue = TSelf.ValidateCharacters(normalized);
        return characterIssue ?? TSelf.ValidateString(normalized);
    }
}
