using System;
using Owasp.Untrust.VV.Core;
using System.Text.RegularExpressions;

namespace Owasp.Untrust.VV.Archetypes;

public abstract class HexString<WrapperT> : HexStringBase<WrapperT>
where WrapperT : HexString<WrapperT>, ICreatable<WrapperT, string>
{
    protected static Bounds<int> _Bounds(int minLength, int maxLength) { return new Bounds<int>(minLength, maxLength); }
    public required Bounds<int> Bounds { get; init; }

    protected override sealed Bounds<int> BoundsConstraint()
    {
        return Bounds;
    }
}
