using System.Diagnostics.CodeAnalysis;

#warning "TEMPORARY: ValidationTraitsPipeline remains as a compatibility bridge; remove it after callers use the replacement validation flow."

namespace Owasp.Untrust.VV.Core;

internal static class ValidationTraitsPipeline
{
    internal static TValue Run<TValue, TTraits>(string raw, IFormatProvider? provider)
        where TValue : notnull, IParsable<TValue>
        where TTraits : IParsableTraits<TValue>
    {
        TValue parsed = ValidationTests.RequireSuccessfulParse<TValue>(
            raw, provider, "value.parse", "The value could not be parsed.");
        TValue normalized = TTraits.NormalizeValue(parsed);
        ValidationTests.RequireNoIssue(TTraits.ValidateValue(normalized));
        return normalized;
    }

    internal static bool TryRun<TValue, TTraits>(
        string? raw,
        IFormatProvider? provider,
        [MaybeNullWhen(false)] out TValue value)
        where TValue : notnull, IParsable<TValue>
        where TTraits : IParsableTraits<TValue>
    {
        if (raw is null)
        {
            value = default;
            return false;
        }

        try
        {
            value = Run<TValue, TTraits>(raw, provider);
            return true;
        }
        catch (ValidationException)
        {
            value = default;
            return false;
        }
    }
}
