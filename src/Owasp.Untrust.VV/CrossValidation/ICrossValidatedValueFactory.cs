#pragma warning disable CS1591

namespace Owasp.Untrust.VV.CrossValidation;

/// <summary>
/// Construction contract for a receiver. The public method is safe because callers
/// cannot construct the required opaque completion value.
/// </summary>
public interface ICrossValidatedValueFactory<TSelf, TValue>
    where TSelf : ICrossValidatedValue
    where TValue : notnull
{
    static abstract TSelf CreateCrossValidated(
        CrossValidationCompletion<TValue, TSelf> completion);
}
