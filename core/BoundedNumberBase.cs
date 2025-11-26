using System.Numerics;
using Owasp.Untrust.VV.Archetypes;

namespace Owasp.Untrust.VV.Core;

public abstract class BoundedNumberBase<WrapperT, ValueT> : ValidatedValue<WrapperT, ValueT, SelfParsableAdapter<ValueT>>
    where WrapperT : BoundedNumberBase<WrapperT, ValueT>, ICreatable<WrapperT, ValueT>
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
