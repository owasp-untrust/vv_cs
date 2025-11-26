using System.ComponentModel.DataAnnotations;
using Owasp.Untrust.VV.Archetypes;

namespace Owasp.Untrust.VV;

public class Email : BoundedString<Email>, ICreatable<Email, string>
{
    public static Email CreateNonValidated(string valueToWrap)
    {
        return new Email { Value = valueToWrap, Bounds = _Bounds(3, 256) };
    }

    protected override bool ExtraValidation()
    {
        return new EmailAddressAttribute().IsValid(Value);
    }
}
