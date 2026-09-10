#pragma warning disable CS1591

using Owasp.Untrust.ValueDescriptors.Core;
using Owasp.Untrust.ValueDescriptors.Disclosure;
using System.Diagnostics.CodeAnalysis;

namespace Owasp.Untrust.VV.Core;

/// <summary>Shared pending state that is publicly representable but deliberately non-exposable.</summary>
public abstract class PendingValue<TSelf, TValue, TReady, TOutput, TTraits, TArchetype, TDisclosure> : IPendingValue, IParsable<TSelf>
    where TValue : notnull
    where TOutput : notnull
    where TSelf : PendingValue<TSelf, TValue, TReady, TOutput, TTraits, TArchetype, TDisclosure>, IInternallyValidatedValueFactory<TSelf, TValue>
    where TReady : IInternallyTransformedValueFactory<TReady, TOutput>
    where TTraits : IValidationTraits<TValue, TDisclosure>
    where TArchetype : IValidationArchetype<TValue>
    where TDisclosure : IDisclosurePolicy<TValue>
{
    private readonly TValue _value;

    protected PendingValue(TValue validatedValue)
    {
        _value = validatedValue ?? throw new ArgumentNullException(nameof(validatedValue));
    }

    public object? ToPublicValue() => TDisclosure.ToPublicValue(_value);

    public string ToPublicString() => TDisclosure.ToPublicString(_value);

    public sealed override string ToString() => ToPublicString();

    public ValueTask<TReady> CompleteAsync(IValueTransformer<TValue, TOutput> transformer, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(transformer);
        return CompleteAsync(transformer.TransformAsync, cancellationToken);
    }

    public async ValueTask<TReady> CompleteAsync(Func<TValue, CancellationToken, ValueTask<TOutput>> transformAsync, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(transformAsync);
        cancellationToken.ThrowIfCancellationRequested();
        TOutput output = await transformAsync(_value, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(output);
        return TReady.CreateTransformed(new InternallyTransformedValue<TOutput, TReady>(output));
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
