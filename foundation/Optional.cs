using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Reflection.Metadata.Ecma335;

namespace Owasp.Untrust.VV.Foundation;

public struct Optional<WrapperT> : IQueryParsable<Optional<WrapperT>>
    where WrapperT : class, IQueryParsable<WrapperT> //, __IWrappableForOptional<WrapperT>
{
    private readonly WrapperT? nullOrValue;

    public static bool TryParse(
        string? asStr,
        IFormatProvider? provider,
        [MaybeNullWhen(false)] out Optional<WrapperT> result)
    {
        if (asStr == null)
        {
            result = new Optional<WrapperT>();
            return true;
        }
        //#pragma warning disable CS8600 // Converting null literal or possible null value to non-nullable type.
        WrapperT? innerObj = null;
        //#pragma warning restore CS8600
        bool success = WrapperT.TryParse(asStr, provider, out innerObj);
        if (success)
        {
            // since success is true I KNOW innerObj is not null
            Debug.Assert(innerObj != null);
            result = new Optional<WrapperT>(innerObj);
            return true;
        }
        else
        {
            result = new Optional<WrapperT>();
            return false;
        }
    }

    /*static bool TryWrap<ValueT>(ValueT? value, out Optional<WrapperT> result)
    {
        if (value == null)
        {
            result = new Optional<WrapperT>();
            return true;
        }

        WrapperT innerObj;
        bool success = WrapperT.__TryWrapBypassingCompileTimeValueTypeCheck(value, out innerObj);
        if (success)
        {
            result = new Optional<WrapperT>(innerObj);
            return true;
        }
        else
        {
            result = new Optional<WrapperT>();
            return false;
        }
    }*/

    public Optional()
    {
        nullOrValue = null;
    }

    public Optional(WrapperT nonNullWrapper)
    {
        nullOrValue = nonNullWrapper;
    }

    public bool HasValue { get { return nullOrValue != null; } }
    public WrapperT NonNull { get {
        if (nullOrValue == null)
        {
            throw new NullReferenceException();
        }
        return nullOrValue;
    }}

    public WrapperT? PossiblyNull { get { return nullOrValue; } }
}
