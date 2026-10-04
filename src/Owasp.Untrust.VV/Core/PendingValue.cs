#pragma warning disable CS1591

using Owasp.Untrust.ValueDescriptors.Core;
using Owasp.Untrust.ValueDescriptors.Disclosure;
using Owasp.Untrust.VV.Traits;
using System.Diagnostics.CodeAnalysis;

namespace Owasp.Untrust.VV.Core;

/// <summary>Shared pending state that is publicly representable but deliberately non-exposable.</summary>
public abstract class PendingValue<TSelf, TValue, TNext, TTransformedVal, TTraits, TDisclosure> 
    : IPendingValue, IParsable<TSelf>
    where TValue : notnull, IParsable<TValue>
    where TTransformedVal : notnull
    where TSelf : PendingValue<TSelf, TValue, TNext, TTransformedVal, TTraits, TDisclosure>, IValidatedValueWrapperFactory<TSelf, TValue>
    where TNext : IInternallyTransformedValueFactory<TNext, TTransformedVal>
    where TTraits : IParsableTraits<TValue>
    where TDisclosure : IDisclosurePolicy<TValue>
{
    private readonly TValue _value;

    protected PendingValue(TValue validatedValue)
    {
        _value = validatedValue ?? throw new ArgumentNullException(nameof(validatedValue));
    }

    public string ToPublicString() => TDisclosure.ToPublicString(_value);

    public sealed override string ToString() => ToPublicString();

    public ValueTask<TNext> CompleteAsync(IValueTransformer<TValue, TTransformedVal> transformer, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(transformer);
        return CompleteAsync(transformer.TransformAsync, cancellationToken);
    }

    public async ValueTask<TNext> CompleteAsync(Func<TValue, CancellationToken, ValueTask<TTransformedVal>> transformAsync, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(transformAsync);
        cancellationToken.ThrowIfCancellationRequested();
        TTransformedVal output = await transformAsync(_value, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(output);
        return TNext.CreateTransformed(new InternallyTransformedValue<TNext, TTransformedVal>(output));
    }

    public static TSelf Parse(string raw, IFormatProvider? provider)
    {
        TValue value = ValidationTraitsPipeline.Run<TValue, TTraits>(raw, provider);
        return TSelf.CreateValidated(new PostValidationRawValue<TValue, TSelf>(value));
    }

    public static bool TryParse(string? raw, IFormatProvider? provider, [MaybeNullWhen(false)] out TSelf result)
    {
        if (ValidationTraitsPipeline.TryRun<TValue, TTraits>(raw, provider, out TValue? value))
        {
            result = TSelf.CreateValidated(new PostValidationRawValue<TValue, TSelf>(value));
            return true;
        }

        result = default;
        return false;
    }
}
