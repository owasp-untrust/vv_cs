using System.ComponentModel.DataAnnotations;
using Owasp.Untrust.VV.Archetypes;

namespace Owasp.Untrust.VV;

public class Phone : BoundedString<Phone>, ICreatable<Phone, string>
{
    public static Phone CreateNonValidated(string valueToWrap)
    {
        return new Phone { Value = valueToWrap, Bounds = _Bounds(3, 256) };
    }

    protected override bool ExtraValidation()
    {
        return new PhoneAttribute().IsValid(Value);
    }
}
