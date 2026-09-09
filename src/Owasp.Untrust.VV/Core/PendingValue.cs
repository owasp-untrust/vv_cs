#pragma warning disable CS1591

using System.Diagnostics.CodeAnalysis;
using Owasp.Untrust.ValueDescriptors.Core;
using Owasp.Untrust.ValueDescriptors.Disclosure;

namespace Owasp.Untrust.VV.Core;

/// <summary>Marks a locally valid value that requires a further transition.</summary>
public interface IPendingValue : IPubliclyRepresentable;

/// <summary>
/// Opaque local-validation evidence. Only this assembly can create an instance;
/// its public value accessor is solely for a receiver's factory/constructor.
/// </summary>
public sealed class InternallyValidatedValue<TValue, TReceiver>
    where TValue : notnull
{
    internal InternallyValidatedValue(TValue value)
    {
        ValueForReadyConstruction = value;
    }

    public TValue ValueForReadyConstruction { get; }
}

public interface IInternallyValidatedValueFactory<TSelf, TValue>
    where TValue : notnull
{
    static abstract TSelf CreateValidated(
        InternallyValidatedValue<TValue, TSelf> validated);
}

/// <summary>Turns a pending primitive into its replacement payload.</summary>
public interface IValueTransformer<in TValue, TOutput>
    where TValue : notnull
    where TOutput : notnull
{
    ValueTask<TOutput> TransformAsync(
        TValue value,
        CancellationToken cancellationToken = default);
}

/// <summary>Opaque transformation evidence emitted only after a transform succeeds.</summary>
public sealed class InternallyTransformedValue<TOutput, TReceiver>
    where TOutput : notnull
{
    internal InternallyTransformedValue(TOutput value)
    {
        ValueForReadyConstruction = value;
    }

    public TOutput ValueForReadyConstruction { get; }
}

public interface IInternallyTransformedValueFactory<TSelf, TOutput>
    where TOutput : notnull
{
    static abstract TSelf CreateTransformed(
        InternallyTransformedValue<TOutput, TSelf> transformed);
}

/// <summary>
/// Shared pending state. It is publicly representable but deliberately does not
/// implement <see cref="IExposableValue{TValue}"/>.
/// </summary>
public abstract class PendingValue<TSelf, TValue, TReady, TOutput, TDisclosure> : IPendingValue
    where TValue : notnull
    where TOutput : notnull
    where TSelf : PendingValue<TSelf, TValue, TReady, TOutput, TDisclosure>
    where TReady : IInternallyTransformedValueFactory<TReady, TOutput>
    where TDisclosure : IDisclosurePolicy<TValue>
{
    private readonly TValue _value;

    protected PendingValue(InternallyValidatedValue<TValue, TSelf> validated)
    {
        ArgumentNullException.ThrowIfNull(validated);
        _value = validated.ValueForReadyConstruction;
    }

    public object? ToPublicValue() => TDisclosure.ToPublicValue(_value);

    public string ToPublicString() => TDisclosure.ToPublicString(_value);

    public sealed override string ToString() => ToPublicString();

    public ValueTask<TReady> CompleteAsync(
        IValueTransformer<TValue, TOutput> transformer,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(transformer);
        return CompleteAsync(transformer.TransformAsync, cancellationToken);
    }

    public async ValueTask<TReady> CompleteAsync(
        Func<TValue, CancellationToken, ValueTask<TOutput>> transformAsync,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(transformAsync);
        cancellationToken.ThrowIfCancellationRequested();
        TOutput output = await transformAsync(_value, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(output);
        return TReady.CreateTransformed(new InternallyTransformedValue<TOutput, TReady>(output));
    }
}

/// <summary>Pending value whose local parsing pipeline is supplied by traits.</summary>
public abstract class PendingFromTraits<TSelf, TValue, TReady, TOutput, TTraits, TArchetype, TDisclosure>
    : PendingValue<TSelf, TValue, TReady, TOutput, TDisclosure>, IParsable<TSelf>
    where TValue : notnull
    where TOutput : notnull
    where TSelf : PendingFromTraits<TSelf, TValue, TReady, TOutput, TTraits, TArchetype, TDisclosure>,
        IInternallyValidatedValueFactory<TSelf, TValue>
    where TReady : IInternallyTransformedValueFactory<TReady, TOutput>
    where TTraits : IValidationTraits<TValue, TDisclosure>
    where TArchetype : IValidationArchetype<TValue>
    where TDisclosure : IDisclosurePolicy<TValue>
{
    protected PendingFromTraits(InternallyValidatedValue<TValue, TSelf> validated)
        : base(validated)
    {
    }

    public static TSelf Parse(string raw, IFormatProvider? provider)
    {
        TValue value = ValidationTraitsPipeline.Run<TValue, TTraits, TArchetype, TDisclosure>(raw, provider);
        return TSelf.CreateValidated(new InternallyValidatedValue<TValue, TSelf>(value));
    }

    public static bool TryParse(string? raw, IFormatProvider? provider, [MaybeNullWhen(false)] out TSelf result)
    {
        if (ValidationTraitsPipeline.TryRun<TValue, TTraits, TArchetype, TDisclosure>(raw, provider, out TValue? value))
        {
            result = TSelf.CreateValidated(new InternallyValidatedValue<TValue, TSelf>(value));
            return true;
        }

        result = default;
        return false;
    }
}
