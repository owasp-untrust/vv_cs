using System.Numerics;
using Owasp.Untrust.VV.Core;

namespace Owasp.Untrust.VV.Archetypes;

public abstract class BoundedNumber<TWrapper, TValue> : BoundedNumberBase<TWrapper, TValue>
    where TWrapper : BoundedNumber<TWrapper, TValue>, ICreatable<TWrapper, TValue>
    where TValue : INumber<TValue>
{
    protected static Bounds<TValue> _Bounds(TValue min, TValue max) { return new Bounds<TValue>(min, max); }
    public required Bounds<TValue> Bounds { get; init; }

    protected override Bounds<TValue> BoundsConstraint() { return Bounds; }
}