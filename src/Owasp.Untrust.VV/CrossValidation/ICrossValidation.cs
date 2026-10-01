#pragma warning disable CS1591

namespace Owasp.Untrust.VV.CrossValidation;

/// <summary>Reusable contextual check for a pending cross-validation candidate.</summary>
public interface ICrossValidation<in TValue>
    where TValue : notnull
{
    ValueTask<CrossValidationResult> ValidateAsync(
        TValue value,
        CancellationToken cancellationToken = default);
}
