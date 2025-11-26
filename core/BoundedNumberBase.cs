using System.Numerics;
using Owasp.Untrust.VV.Archetypes;

namespace Owasp.Untrust.VV.Core;

public abstract class BoundedNumberBase<TWrapper, ValueT> : ValidatedValue<TWrapper, ValueT, SelfParsableAdapter<ValueT>>
    where TWrapper : BoundedNumberBase<TWrapper, ValueT>, ICreatable<TWrapper, ValueT>
    where ValueT : INumber<ValueT>
{
    protected abstract Bounds<ValueT> BoundsConstraint();

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
