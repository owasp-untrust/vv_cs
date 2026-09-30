using System.Numerics;
using Owasp.Untrust.ValueDescriptors.Disclosure;

namespace Owasp.Untrust.VV.Core;

public abstract class BoundedNumber<TSelf, TValue, TDisclosure>
    : ValidatedParsableFromTraits<TSelf, TValue, TSelf, TDisclosure>
    , IParsableTraits<TValue>
    , IParsable<TSelf>
    where TSelf : BoundedNumber<TSelf, TValue, TDisclosure>
        , IValidatedValueWrapperFactory<TSelf, TValue>
        , IBoundedNumber<TValue>
    where TValue : notnull, INumber<TValue>
    where TDisclosure : IDisclosurePolicy<TValue>
{
    protected BoundedNumber(TValue validatedValue) : base(validatedValue) { }

    public static TValue NormalizeValue(TValue value) => value;

    public static ValidationIssue? ValidateValue(TValue value)
        => TSelf.Bounds.Contains(value) ? null : new ValidationIssue("number.bounds", "The number is outside the allowed range.");
}
