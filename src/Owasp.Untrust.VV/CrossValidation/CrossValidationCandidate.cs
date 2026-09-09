#pragma warning disable CS1591
using System.Diagnostics.CodeAnalysis;
using Owasp.Untrust.VV.Core;
using Owasp.Untrust.ValueDescriptors.Disclosure;

namespace Owasp.Untrust.VV.CrossValidation;

/// <summary>
/// Holds a locally validated value without exposing it. A leaf supplies a
/// domain-specific asynchronous check and receives a different receiver type only
/// after that check succeeds.
/// </summary>
public abstract class CrossValidationCandidate<
    TCandidate,
    TValue,
    TReceiver,
    TTraits,
    TArchetype,
    TDisclosure> : ICrossValidationCandidate, IParsable<TCandidate>
    where TCandidate : CrossValidationCandidate<TCandidate, TValue, TReceiver, TTraits, TArchetype, TDisclosure>,
        ICrossValidationCandidateFactory<TCandidate, TValue>
    where TValue : notnull
    where TReceiver : CrossValidatedValue<TReceiver, TValue, TDisclosure>,
        ICrossValidatedValueFactory<TReceiver, TValue>
    where TTraits : IValidationTraits<TValue, TDisclosure>
    where TArchetype : IValidationArchetype<TValue>
    where TDisclosure : IDisclosurePolicy<TValue>
{
    private readonly TValue _locallyValidated;

    protected CrossValidationCandidate(TValue locallyValidated)
    {
        _locallyValidated = locallyValidated ?? throw new ArgumentNullException(nameof(locallyValidated));
    }

    public Type ReceiverType => typeof(TReceiver);

    public object? ToPublicValue() =>
        TDisclosure.ToPublicValue(_locallyValidated);

    public string ToPublicString() =>
        TDisclosure.ToPublicString(_locallyValidated);

    public sealed override string ToString() => ToPublicString();

    public ValueTask<TReceiver> CompleteAsync(
        ICrossValidation<TValue> validation,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(validation);
        return CompleteCrossValidationAsync(validation.ValidateAsync, cancellationToken);
    }

    public ValueTask<TReceiver> CompleteAsync(
        Func<TValue, CancellationToken, ValueTask<CrossValidationResult>> validateAsync,
        CancellationToken cancellationToken = default) =>
        CompleteCrossValidationAsync(validateAsync, cancellationToken);

    public static TCandidate Parse(string text, IFormatProvider? provider)
    {
        TValue validated = ValidationTraitsPipeline.Run<TValue, TTraits, TArchetype, TDisclosure>(text, provider);
        return TCandidate.CreateValidated(new InternallyValidatedValue<TValue, TCandidate>(validated));
    }

    public static bool TryParse(
        string? text,
        IFormatProvider? provider,
        [NotNullWhen(true)] out TCandidate? result)
    {
        if (ValidationTraitsPipeline.TryRun<TValue, TTraits, TArchetype, TDisclosure>(
                text,
                provider,
                out TValue? locallyValidated))
        {
            result = TCandidate.CreateValidated(new InternallyValidatedValue<TValue, TCandidate>(locallyValidated));
            return true;
        }

        result = null;
        return false;
    }

    /// <summary>
    /// Runs a leaf-owned contextual check and mints opaque receiver evidence only
    /// for a successful result. I/O never occurs in parsing or construction.
    /// </summary>
    protected async ValueTask<TReceiver> CompleteCrossValidationAsync(
        Func<TValue, CancellationToken, ValueTask<CrossValidationResult>> validateAsync,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(validateAsync);
        cancellationToken.ThrowIfCancellationRequested();

        CrossValidationResult result = await validateAsync(
                _locallyValidated,
                cancellationToken)
            .ConfigureAwait(false);

        cancellationToken.ThrowIfCancellationRequested();
        if (!result.Succeeded)
        {
            throw new CrossValidationException(result);
        }

        CrossValidationCompletion<TValue, TReceiver> completion =
            new(_locallyValidated);
        return TReceiver.CreateCrossValidated(completion);
    }
}

/// <summary>Library-only construction hook implemented explicitly by a candidate leaf.</summary>
public interface ICrossValidationCandidateFactory<TSelf, TValue>
    where TValue : notnull
{
    static abstract TSelf CreateValidated(
        InternallyValidatedValue<TValue, TSelf> locallyValidatedValue);
}
