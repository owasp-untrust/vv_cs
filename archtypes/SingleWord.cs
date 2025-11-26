using Owasp.Untrust.VV.Core;

namespace Owasp.Untrust.VV.Archetypes;

public abstract class SingleWord<TWrapper> : RegexStringBase<TWrapper>
    where TWrapper : SingleWord<TWrapper>, ICreatable<TWrapper, string>
{
    protected static Bounds<int> _Bounds(int min, int max) { return new Bounds<int>(min, max); }
    public required Bounds<int> Bounds { get; init; }

    protected override Bounds<int> BoundsConstraint() { return Bounds; }
    protected sealed override string PatternConstraint() { return "^[A-Za-z]+$"; }
    protected sealed override Type? SharedRegexKey() { return typeof(SingleWord<>); }
}
