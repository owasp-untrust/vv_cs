using System.ComponentModel.DataAnnotations;
using Owasp.Untrust.VV.Core;
using Owasp.Untrust.VV.Archetypes;

namespace Owasp.Untrust.VV;

public class CreditCard : BoundedAnyContentStringBase<CreditCard>, ICreatable<CreditCard, string>
{
    private static Bounds<int> BOUNDS = new Bounds<int>(8, 20);

    public static CreditCard CreateNonValidated(string valueToWrap)
    {
        return new CreditCard { Value = valueToWrap };
    }

    protected override Bounds<int> BoundsConstraint()
    {
        return BOUNDS;
    }
    
    protected override bool ExtraValidation()
    {
        return new CreditCardAttribute().IsValid(Value);
    }
}
