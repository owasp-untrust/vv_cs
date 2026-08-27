#pragma warning disable CS1591

namespace Owasp.Untrust.VV.Core;

/// <summary>
/// Indicates rejected untrusted input. The exception intentionally does not retain
/// or render the rejected value.
/// </summary>
public sealed class ValidationException : FormatException
{
    public ValidationException(ValidationIssue issue)
        : base((issue ?? throw new ArgumentNullException(nameof(issue))).Message)
    {
        Issue = issue;
    }

    public ValidationIssue Issue { get; }

    public string Code => Issue.Code;
}
