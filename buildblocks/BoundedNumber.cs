using System.Numerics;

using Owasp.Untrust.VV.Foundation;

namespace Owasp.Untrust.VV.Build;

public abstract class BoundedNumber<WrapperT, ValueT> : ValidatedValue<WrapperT, ValueT, SelfParsableAdapter<ValueT>>
    where WrapperT : BoundedNumber<WrapperT, ValueT>, ICreatable<WrapperT, ValueT>
    where ValueT : INumber<ValueT>
{
    protected static Bounds<ValueT> _Bounds(ValueT min, ValueT max) { return new Bounds<ValueT>(min, max); }
    public required Bounds<ValueT> Bounds { get; init; }

    protected override ValidationResultHolder ChainableValidation()
    {
        ValidationResultHolder result = base.ChainableValidation();
        if (Value < Bounds.Min || Value > Bounds.Max)
        {
            result.Invalidate();
        }
        return result;
    }
}
