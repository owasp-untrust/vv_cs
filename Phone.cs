using System.ComponentModel.DataAnnotations;
using Owasp.Untrust.VV.Core;
using Owasp.Untrust.VV.Archetypes;

namespace Owasp.Untrust.VV;

public class Phone : BoundedAnyContentStringBase<Phone>, ICreatable<Phone, string>
{
    private static Bounds<int> BOUNDS = new Bounds<int>(3, 20);

    public static Phone CreateNonValidated(string valueToWrap)
    {
        return new Phone { Value = valueToWrap };
    }

    protected override Bounds<int> BoundsConstraint()
    {
        return BOUNDS;
    }

    protected override bool ExtraValidation()
    {
        return new PhoneAttribute().IsValid(Value);
    }
}
