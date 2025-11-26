using System.Numerics;
using Owasp.Untrust.VV.Core;

namespace Owasp.Untrust.VV.Archetypes;

public abstract class SingleLine<TWrapper, TTabPolicy> : BoundedAnyContentStringBase<TWrapper>
    where TWrapper : SingleLine<TWrapper, TTabPolicy>, ICreatable<TWrapper, string>
    where TTabPolicy : TabPolicy
{
    protected static Bounds<int> _Bounds(int minLength, int maxLength) { return new Bounds<int>(minLength, maxLength); }
    public required Bounds<int> Bounds { get; init; }

    protected override sealed Bounds<int> BoundsConstraint()
    {
        return Bounds;
    }

    protected override ValidationResultHolder ChainableValidation() {
        ValidationResultHolder result = base.ChainableValidation();
        if (!result.IsValid) {
            return result;
        }

        foreach (char c in Value.ToCharArray())
        {
            if (char.IsControl(c) || char.IsHighSurrogate(c) || char.IsLowSurrogate(c))
            {
                if (c != '\t' || !TTabPolicy.AllowTab())
                {
                    result.Invalidate();
                    break;
                }
            }
        }
        return result;
    }
}
