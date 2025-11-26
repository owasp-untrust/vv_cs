using System.Numerics;
using Owasp.Untrust.VV.Archetypes;

namespace Owasp.Untrust.VV.Core;

public abstract class BoundedStringBase<WrapperT> : ValidatedValue<WrapperT, string, SelfParsableAdapter<string>>
    where WrapperT : BoundedStringBase<WrapperT>, ICreatable<WrapperT, string>
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
