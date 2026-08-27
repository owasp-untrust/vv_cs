#pragma warning disable CS1591

namespace Owasp.Untrust.VV.Core;

/// <summary>A stable, safe-to-report validation failure.</summary>
/// <param name="Code">A machine-readable code that never contains input.</param>
/// <param name="Message">A safe developer-facing message that never contains input.</param>
public sealed record ValidationIssue(string Code, string Message)
{
    public static ValidationIssue Required { get; } =
        new("value.required", "A value is required.");

    public static ValidationIssue InvalidFormat { get; } =
        new("value.invalid_format", "The value has an invalid format.");
}
