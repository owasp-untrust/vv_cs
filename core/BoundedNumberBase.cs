using System.Numerics;
using Owasp.Untrust.VV.Archetypes;

namespace Owasp.Untrust.VV.Core;

public abstract class BoundedNumberBase<TWrapper, TValue> : ValidatedValue<TWrapper, TValue, SelfParsableAdapter<TValue>>
    where TWrapper : BoundedNumberBase<TWrapper, TValue>, ICreatable<TWrapper, TValue>
    where TValue : INumber<TValue>
{
    protected abstract Bounds<TValue> BoundsConstraint();

    protected override ValidationResultHolder ChainableValidation()
    {
        ValidationResultHolder result = base.ChainableValidation();
        if (Value < BoundsConstraint().Min || Value > BoundsConstraint().Max)
        {
            result.Invalidate();
        }
        return result;
    }
}
