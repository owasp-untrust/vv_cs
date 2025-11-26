using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Security;
using Owasp.Untrust.VV.Archetypes;

namespace Owasp.Untrust.VV.Core;

public abstract class ValidatedValue<TWrapper, ValueT, ParserT> 
: IQueryParsable<TWrapper> //, __IWrappableForOptional<TWrapper>
    where TWrapper : ValidatedValue<TWrapper, ValueT, ParserT>, ICreatable<TWrapper, ValueT>
    where ParserT : IQueryParsable<ValueT>
    where ValueT : notnull
{
    public required ValueT Value { get; init; }

    public static bool TryParse(
        string? asStr,
        IFormatProvider? provider,
        [MaybeNullWhen(false)] out TWrapper result)
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

    public static bool TryWrap(ValueT value, out TWrapper result)
    {
        result = TWrapper.CreateNonValidated(value);
        if (result.ChainableValidation().IsValid)
        {
            if (result.ExtraValidation())
            {
                return true;
            }
        }

        return false;
    }

    public static TWrapper Wrap(ValueT value)
    {
        TWrapper result;
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
    static bool __IWrappableForOptional<TWrapper>.__TryWrapBypassingCompileTimeValueTypeCheck(object valueAsObj, out TWrapper result)
    {
        Debug.Assert(valueAsObj is ValueT);
        return TryWrap((ValueT)valueAsObj, out result);
    }*/
}
