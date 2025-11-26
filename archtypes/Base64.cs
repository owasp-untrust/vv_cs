using Owasp.Untrust.VV.Core;

namespace Owasp.Untrust.VV.Archetypes;

public abstract class Base64<TWrapper, TVariant> : Base64Base<TWrapper, TVariant>
    where TWrapper : Base64<TWrapper, TVariant>, ICreatable<TWrapper, string>
    where TVariant : Base64Variant
{
    protected static Bounds<int> _Bounds(int min, int max) { return new Bounds<int>(min, max); }
    public required Bounds<int> Bounds { get; init; }

    protected override Bounds<int> BoundsConstraint() { return Bounds; }
}
