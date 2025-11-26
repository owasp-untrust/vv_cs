using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Security;
using Owasp.Untrust.VV.Archetypes;

namespace Owasp.Untrust.VV.Core;

public abstract class ValidatedValue<WrapperT, ValueT, ParserT> 
: IQueryParsable<WrapperT> //, __IWrappableForOptional<WrapperT>
    where WrapperT : ValidatedValue<WrapperT, ValueT, ParserT>, ICreatable<WrapperT, ValueT>
    where ParserT : IQueryParsable<ValueT>
    where ValueT : notnull
{
    public required ValueT Value { get; init; }

    public static bool TryParse(
        string? asStr,
        IFormatProvider? provider,
        [MaybeNullWhen(false)] out WrapperT result)
    {
        if (asStr != null) {
            ValueT value;
            #pragma warning disable CS8600 // Converting null literal or possible null value to non-nullable type.
            if (ParserT.TryParse(asStr, provider, out value))
            {
                return TryWrap(value, out result);
            }
            #pragma warning restore CS8600 // Converting null literal or possible null value to non-nullable type.
        }

        result = default;
        return false;
    }

    public static bool TryWrap(ValueT value, out WrapperT result)
    {
        result = WrapperT.CreateNonValidated(value);
        if (result.ChainableValidation().IsValid)
        {
            if (result.ExtraValidation())
            {
                return true;
            }
        }

        return false;
    }

    public static WrapperT Wrap(ValueT value)
    {
        WrapperT result;
        if (!TryWrap(value, out result))
        {
            throw new FormatException("Invalid input");
        }
        
        return result;
    }

    protected ValidatedValue()
    {
    }

    protected ValidatedValue(ValueT value)
    {
        this.Value = value;
    }

    protected abstract bool ExtraValidation();

    protected struct ValidationResultHolder
    {
        private bool isValid;
        public bool IsValid { get { return isValid; } }
        internal ValidationResultHolder(bool initialVal) { isValid = initialVal; }
        public void Invalidate() { isValid = false; }
    }
    protected virtual ValidationResultHolder ChainableValidation() { return new ValidationResultHolder(true); }

    /*[EditorBrowsable(EditorBrowsableState.Never)]
    static bool __IWrappableForOptional<WrapperT>.__TryWrapBypassingCompileTimeValueTypeCheck(object valueAsObj, out WrapperT result)
    {
        Debug.Assert(valueAsObj is ValueT);
        return TryWrap((ValueT)valueAsObj, out result);
    }*/
}
