#pragma warning disable CS1591
using Owasp.Untrust.VV.Core;
using Owasp.Untrust.ValueDescriptors.Core;

namespace Owasp.Untrust.VV.CrossValidation;

/// <summary>
/// Marks a locally validated candidate that still requires contextual validation.
/// ASP.NET integration uses this marker to reject response serialization.
/// </summary>
public interface ICrossValidationCandidate : IPubliclyRepresentable
{
    Type ReceiverType { get; }
}

/// <summary>Reusable contextual check for a pending cross-validation candidate.</summary>
public interface ICrossValidation<in TValue>
    where TValue : notnull
{
    ValueTask<CrossValidationResult> ValidateAsync(
        TValue value,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Marks a value whose contextual validation has completed. ASP.NET integration
/// uses this marker to reject direct request deserialization.
/// </summary>
public interface ICrossValidatedValue : IValidatedValue;

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
