using System.Numerics;

using Owasp.Untrust.VV.Core;

namespace Owasp.Untrust.VV.Archetypes;

public abstract class BoundedNumber<WrapperT, ValueT> : BoundedNumberBase<WrapperT, ValueT>
    where WrapperT : BoundedNumber<WrapperT, ValueT>, ICreatable<WrapperT, ValueT>
    where ValueT : INumber<ValueT>
{
    protected static Bounds<ValueT> _Bounds(ValueT min, ValueT max) { return new Bounds<ValueT>(min, max); }
    public required Bounds<ValueT> Bounds { get; init; }

    protected override Bounds<ValueT> BoundsConstraint() { return Bounds; }
}