using System.Numerics;
using Owasp.Untrust.VV.Core;

namespace Owasp.Untrust.VV.Archetypes;

public abstract class BoundedString<WrapperT> : BoundedStringBase<WrapperT>
    where WrapperT : BoundedString<WrapperT>, ICreatable<WrapperT, string>
{
    protected static Bounds<int> _Bounds(int minLength, int maxLength) { return new Bounds<int>(minLength, maxLength); }
    public required Bounds<int> Bounds { get; init; }

    protected override sealed Bounds<int> BoundsConstraint()
    {
        return Bounds;
    }
}
