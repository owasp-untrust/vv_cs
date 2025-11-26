using System.ComponentModel.DataAnnotations;
using Owasp.Untrust.VV.Core;
using Owasp.Untrust.VV.Archetypes;

namespace Owasp.Untrust.VV;

public class Email : BoundedAnyContentStringBase<Email>, ICreatable<Email, string>
{
    private static Bounds<int> BOUNDS = new Bounds<int>(5, 256);

    public static Email CreateNonValidated(string valueToWrap)
    {
        return new Email { Value = valueToWrap };
    }

    protected override Bounds<int> BoundsConstraint()
    {
        return BOUNDS;
    }
    
    protected override bool ExtraValidation()
    {
        return new EmailAddressAttribute().IsValid(Value);
    }
}
