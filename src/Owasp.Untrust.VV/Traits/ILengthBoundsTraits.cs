using Owasp.Untrust.VV.Core;

namespace Owasp.Untrust.VV.Traits;

/// <summary>Traits selecting mandatory bounded-string enforcement.</summary>
public interface ILengthBoundsTraits<TSelf>
    where TSelf : ILengthBoundsTraits<TSelf>
{
    static abstract Bounds<int> LengthBounds { get; }
}
