namespace Owasp.Untrust.VV.Core;

internal delegate bool TryParseValue<TValue>(out TValue? value)
    where TValue : notnull;

internal static class ValidationTests
{
    internal static string RequireNotNull(string? raw)
    {
        if (raw is null)
        {
            throw new ValidationException(ValidationIssue.Required);
        }

        return raw;
    }

    internal static void Require(bool condition, string code, string message)
    {
        if (!condition)
        {
            throw new ValidationException(new ValidationIssue(code, message));
        }
    }

    internal static TValue RequireSuccessfulParse<TValue>(
        string raw,
        IFormatProvider? provider,
        string code,
        string message)
        where TValue : notnull, IParsable<TValue> =>
        RequireSuccessfulParse<TValue>(
            (out TValue? value) => TValue.TryParse(raw, provider, out value),
            code,
            message);

    internal static TValue RequireSuccessfulParse<TValue>(
        TryParseValue<TValue> tryParse,
        string code,
        string message)
        where TValue : notnull
    {
        ArgumentNullException.ThrowIfNull(tryParse);

        if (!tryParse(out TValue? value) || value is null)
        {
            throw new ValidationException(new ValidationIssue(code, message));
        }

        return value;
    }

    internal static void RequireNoIssue(ValidationIssue? issue)
    {
        if (issue is not null)
        {
            throw new ValidationException(issue);
        }
    }
}
