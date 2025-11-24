using System.Numerics;
using Owasp.Untrust.VV.Foundation;

namespace Owasp.Untrust.VV.Build;

public abstract class BoundedString<WrapperT> : ValidatedValue<WrapperT, string, SelfParsableAdapter<string>>
    where WrapperT : BoundedString<WrapperT>, ICreatable<WrapperT, string>
{
    protected static Bounds<uint> _Bounds(uint minLength, uint maxLength) { return new Bounds<uint>(minLength, maxLength); }
    public required Bounds<uint> Bounds { get; init; }

    protected override ValidationResultHolder ChainableValidation()
    {
        ValidationResultHolder result = base.ChainableValidation();
        if (Value.Length < Bounds.Min || Value.Length > Bounds.Max)
        {
            result.Invalidate();
        }
        return result;
    }
}
