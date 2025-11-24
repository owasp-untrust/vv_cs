using Owasp.Untrust.VV.Foundation;

namespace Owasp.Untrust.VV.Build;

class Distinct<TValue> : HashSet<TValue>
{
    protected static Bounds<uint> _Bounds(uint minLength, uint maxLength) { return new Bounds<uint>(minLength, maxLength); }
    public required Bounds<uint> Bounds { get; init; }
}
