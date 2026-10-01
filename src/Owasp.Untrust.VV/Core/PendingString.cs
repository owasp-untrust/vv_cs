#pragma warning disable CS1591

using Owasp.Untrust.ValueDescriptors.Core;
using Owasp.Untrust.ValueDescriptors.Disclosure;
using Owasp.Untrust.VV.Core.StringPreprocessing;
using System.Diagnostics.CodeAnalysis;
using System.Diagnostics;

namespace Owasp.Untrust.VV.Core;

/// <summary>Shared pending state that is publicly representable but deliberately non-exposable.</summary>
public abstract class PendingString<TSelf, TNext, TTransformedVal, TTraits> 
    : StringValidatedByTraits<TSelf, TTraits, PendingString<TSelf, TNext, TTransformedVal, TTraits>.NeverDisclosed>
    , IPendingValue
    where TSelf : PendingString<TSelf, TNext, TTransformedVal, TTraits>
        , IValidatedValueWrapperFactory<TSelf, string>
    where TNext : IInternallyTransformedValueFactory<TNext, TTransformedVal>
    where TTransformedVal : notnull
    where TTraits : IStringTraitsAnonymousPreprocessing<TTraits>
{
    protected PendingString(string validatedValue)
        : base(validatedValue)
    {
    }

    public ValueTask<TNext> CompleteAsync(IValueTransformer<string, TTransformedVal> transformer, CancellationToken cancellationToken = default)
    {
        Debug.Assert(transformer is not null, "Transformer is not an optional value, so it should never be null.");
        return CompleteAsync(transformer.TransformAsync, cancellationToken);
    }

    public async ValueTask<TNext> CompleteAsync(Func<string, CancellationToken, ValueTask<TTransformedVal>> transformAsync, CancellationToken cancellationToken = default)
    {
        Debug.Assert(transformAsync is not null, "Transform function is not an optional value, so it should never be null.");

        cancellationToken.ThrowIfCancellationRequested();
        TTransformedVal output = await transformAsync(GetValidatedValueForDerivedUse(), cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(output); // must check this since transformAsync come from developer
        return TNext.CreateTransformed(new InternallyTransformedValue<TNext, TTransformedVal>(output));
    }

    public class NeverDisclosed : IDisclosurePolicy<string>
    {
        public static string ToPublicString(string value) => "Pending String";
    }
}

[AttributeUsage(AttributeTargets.Class, AllowMultiple = false, Inherited = false)]
public sealed class PendingStringFromTraitsAttribute<TNext, TTransformedVal, TTraits> : Attribute;
