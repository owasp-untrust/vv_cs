#pragma warning disable CS1591

namespace Owasp.Untrust.VV.CrossValidation;

/// <summary>
/// Opaque, receiver-specific evidence emitted only after successful contextual
/// validation. It intentionally exposes no public state and has no public
/// constructor.
/// </summary>
public sealed class CrossValidationCompletion<TValue, TReceiver>
    where TReceiver : ICrossValidatedValue
    where TValue : notnull
{
    private readonly TValue _validatedValue;

    internal CrossValidationCompletion(TValue validatedValue)
    {
        _validatedValue = validatedValue;
    }

    internal TValue ValidatedValue => _validatedValue;
}
