namespace Owasp.Untrust.VV.Core;

internal static class ValidationPipeline
{
    internal static string RequireRaw(string? raw)
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

    internal static void RequireNoIssue(ValidationIssue? issue)
    {
        if (issue is not null)
        {
            throw new ValidationException(issue);
        }
    }
}
