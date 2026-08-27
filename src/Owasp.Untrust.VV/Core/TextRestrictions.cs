namespace Owasp.Untrust.VV.Core;

/// <summary>A reusable rule that can only further restrict already-safe line text.</summary>
public interface ITextRestriction
{
    static abstract ValidationIssue? Validate(string value);
}

/// <summary>An explicit decision not to add a domain-specific restriction.</summary>
public readonly struct NoAdditionalTextRestriction : ITextRestriction
{
    public static ValidationIssue? Validate(string value) => null;
}

/// <summary>Requires both restrictions to accept the value.</summary>
public readonly struct AllOf<TFirst, TSecond> : ITextRestriction
    where TFirst : ITextRestriction
    where TSecond : ITextRestriction
{
    public static ValidationIssue? Validate(string value) =>
        TFirst.Validate(value) ?? TSecond.Validate(value);
}

/// <summary>Rejects leading or trailing Unicode whitespace.</summary>
public readonly struct NoLeadingOrTrailingWhitespace : ITextRestriction
{
    public static ValidationIssue? Validate(string value) =>
        value.Length == 0 || (!char.IsWhiteSpace(value[0]) && !char.IsWhiteSpace(value[^1]))
            ? null
            : new ValidationIssue(
                "text.edge_whitespace",
                "Leading or trailing whitespace is not allowed.");
}

/// <summary>Rejects adjacent Unicode whitespace characters.</summary>
public readonly struct NoRepeatedWhitespace : ITextRestriction
{
    public static ValidationIssue? Validate(string value)
    {
        for (int index = 1; index < value.Length; index++)
        {
            if (char.IsWhiteSpace(value[index - 1]) && char.IsWhiteSpace(value[index]))
            {
                return new ValidationIssue(
                    "text.repeated_whitespace",
                    "Repeated whitespace is not allowed.");
            }
        }

        return null;
    }
}

/// <summary>Rejects slash and backslash even when full path-safe mode is unnecessary.</summary>
public readonly struct NoPathSeparators : ITextRestriction
{
    public static ValidationIssue? Validate(string value) =>
        value.IndexOfAny(['/', '\\']) < 0
            ? null
            : new ValidationIssue("text.path_separator", "Path separators are not allowed.");
}
