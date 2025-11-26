using System.Numerics;
using Owasp.Untrust.VV.Archetypes;

namespace Owasp.Untrust.VV.Core;

public abstract class BoundedAnyContentStringBase<TWrapper> : ValidatedValue<TWrapper, string, SelfParsableAdapter<string>>
    where TWrapper : BoundedAnyContentStringBase<TWrapper>, ICreatable<TWrapper, string>
{
    protected abstract Bounds<int> BoundsConstraint();

    protected override ValidationResultHolder ChainableValidation()
    {
        ValidationResultHolder result = base.ChainableValidation();
        if (Value.Length < BoundsConstraint().Min || Value.Length > BoundsConstraint().Max)
        {
            result.Invalidate();
        }
        return result;
    }
}
