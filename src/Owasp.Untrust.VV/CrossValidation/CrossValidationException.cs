#pragma warning disable CS1591
namespace Owasp.Untrust.VV.CrossValidation;

/// <summary>
/// Reports a contextual validation failure without retaining or formatting the
/// rejected value.
/// </summary>
public sealed class CrossValidationException : Exception
{
    internal CrossValidationException(CrossValidationResult result)
        : base(result.SafeMessage ?? "The value failed cross-validation.")
    {
        ErrorCode = result.ErrorCode ?? "cross_validation_failed";
    }

    public string ErrorCode { get; }
}
