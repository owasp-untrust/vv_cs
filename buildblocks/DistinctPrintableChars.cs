using Owasp.Untrust.VV.Foundation;

namespace Owasp.Untrust.VV.Build;

public abstract class DistinctPrintableChars<WrapperT> : BoundedString<WrapperT>
    where WrapperT : DistinctPrintableChars<WrapperT>, ICreatable<WrapperT, string>
{
    protected override ValidationResultHolder ChainableValidation()
    {
        ValidationResultHolder result = base.ChainableValidation();
        if (Value.Distinct().Count() != Value.Length)
        {
                result.Invalidate();
        }
        else
        {
            foreach (char c in Value.ToCharArray())
            {
                if (char.IsControl(c) || char.IsHighSurrogate(c) || char.IsLowSurrogate(c))
                {
                    result.Invalidate();
                    break;
                }
            }
        }
        return result;
    }
}
