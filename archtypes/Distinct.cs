using Owasp.Untrust.VV.Core;

namespace Owasp.Untrust.VV.Archetypes;

class Distinct<TValue> : HashSet<TValue>
{
    protected static Bounds<int> _Bounds(int minLength, int maxLength) { return new Bounds<int>(minLength, maxLength); }
    public required Bounds<int> Bounds { get; init; }
}
