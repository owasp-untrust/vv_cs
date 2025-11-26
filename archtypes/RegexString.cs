using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text.RegularExpressions;
using Owasp.Untrust.VV.Core;

namespace Owasp.Untrust.VV.Archetypes;

public abstract class RegexString<WrapperT> : RegexStringBase<WrapperT>
   where WrapperT : RegexString<WrapperT>, ICreatable<WrapperT, string>
{
    protected static Bounds<int> _Bounds(int minLength, int maxLength) { return new Bounds<int>(minLength, maxLength); }
    public required Bounds<int> Bounds { get; init; }
    public required string Pattern { get; init; }

    protected override sealed Bounds<int> BoundsConstraint()
    {
        return Bounds;
    }

    protected override sealed string PatternConstraint() 
    {
        return Pattern;
    }
}    
