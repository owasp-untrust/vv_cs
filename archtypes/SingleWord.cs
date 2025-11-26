using Owasp.Untrust.VV.Core;

namespace Owasp.Untrust.VV.Archetypes;

public abstract class SingleWord<WrapperT> : BoundedString<WrapperT>
    where WrapperT : SingleWord<WrapperT>, ICreatable<WrapperT, string>
{
    protected override ValidationResultHolder ChainableValidation()
    {
        ValidationResultHolder result = base.ChainableValidation();
        foreach (char c in Value.ToCharArray())
        {
            if (!char.IsAsciiLetter(c))
            {
                result.Invalidate();
                break;
            }
        }
        return result;
    }
}
