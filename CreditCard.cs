using System.ComponentModel.DataAnnotations;
using Owasp.Untrust.VV.Build;
using Owasp.Untrust.VV.Foundation;

namespace Owasp.Untrust.VV;

public class CreditCard : BoundedString<CreditCard>, ICreatable<CreditCard, string>
{
    public static CreditCard CreateNonValidated(string valueToWrap)
    {
        return new CreditCard { Value = valueToWrap, Bounds = _Bounds(3, 256) };
    }

    protected override bool ExtraValidation()
    {
        return new CreditCardAttribute().IsValid(Value);
    }
}
