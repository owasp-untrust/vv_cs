#pragma warning disable CS1591

namespace Owasp.Untrust.VV.Core;

/// <summary>
/// Library construction hook used by generic validation bases to create their leaf value.
/// </summary>
/// <remarks>
/// A leaf normally implements this interface explicitly so <c>CreateValidated</c>
/// does not become part of its ordinary public API:
/// <code>
/// static CreditCard IValidatedValueWrapperFactory&lt;CreditCard, string&gt;.CreateValidated(
///     PostValidationRawValue&lt;string, CreditCard&gt; validated) =&gt;
///     new(validated.ValueForReadyConstruction);
/// </code>
/// The alternative implicit implementation is public:
/// <code>
/// public static CreditCard CreateValidated(
///     PostValidationRawValue&lt;string, CreditCard&gt; validated) =&gt;
///     new(validated.ValueForReadyConstruction);
/// </code>
/// That public form does not let library consumers bypass validation: the
/// <see cref="PostValidationRawValue{TValue, TReceiver}"/> constructor is internal,
/// so consumers cannot create its required evidence. Explicit implementation is
/// nevertheless preferable because it keeps the leaf API cleaner; it is not a
/// security boundary or a substitute for validation.
/// </remarks>
public interface IValidatedValueWrapperFactory<TSelf, TValue>
    where TSelf : IValidatedValueWrapperFactory<TSelf, TValue>
    where TValue : notnull
{
    static abstract TSelf CreateValidated(PostValidationRawValue<TValue, TSelf> validated);
}
