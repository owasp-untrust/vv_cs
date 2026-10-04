namespace Owasp.Untrust.VV.Core;

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
        where TValue : notnull, IParsable<TValue>
    {
        if (!TValue.TryParse(raw, provider, out TValue? value) || value is null)
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
