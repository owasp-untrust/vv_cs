using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Security;
using Owasp.Untrust.VV.Archetypes;

namespace Owasp.Untrust.VV.Core;

public abstract class ValidatedValue<TWrapper, TValue, TParser> 
: IQueryParsable<TWrapper> //, __IWrappableForOptional<TWrapper>
    where TWrapper : ValidatedValue<TWrapper, TValue, TParser>, ICreatable<TWrapper, TValue>
    where TParser : IQueryParsable<TValue>
    where TValue : notnull
{
    public required TValue Value { get; init; }

    public static bool TryParse(
        string? asStr,
        IFormatProvider? provider,
        [MaybeNullWhen(false)] out TWrapper result)
    {
        if (asStr != null) {
            TValue value;
            #pragma warning disable CS8600 // Converting null literal or possible null value to non-nullable type.
            if (TParser.TryParse(asStr, provider, out value))
            {
                return TryWrap(value, out result);
            }
            #pragma warning restore CS8600 // Converting null literal or possible null value to non-nullable type.
        }

        result = default;
        return false;
    }

    public static bool TryWrap(TValue value, out TWrapper result)
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

    public static TWrapper Wrap(TValue value)
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

    protected ValidatedValue(TValue value)
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
        Debug.Assert(valueAsObj is TValue);
        return TryWrap((TValue)valueAsObj, out result);
    }*/
}
