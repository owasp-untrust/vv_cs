using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

using Owasp.Untrust.VV.Core;

namespace Owasp.Untrust.VV;

public struct Optional<TWrapper> : IQueryParsable<Optional<TWrapper>>
    where TWrapper : class, IQueryParsable<TWrapper> //, __IWrappableForOptional<TWrapper>
{
    private readonly TWrapper? nullOrValue;

    public static bool TryParse(
        string? asStr,
        IFormatProvider? provider,
        [MaybeNullWhen(false)] out Optional<TWrapper> result)
    {
        if (asStr == null)
        {
            result = new Optional<TWrapper>();
            return true;
        }
        //#pragma warning disable CS8600 // Converting null literal or possible null value to non-nullable type.
        TWrapper? innerObj = null;
        //#pragma warning restore CS8600
        bool success = TWrapper.TryParse(asStr, provider, out innerObj);
        if (success)
        {
            // since success is true I KNOW innerObj is not null
            Debug.Assert(innerObj != null);
            result = new Optional<TWrapper>(innerObj);
            return true;
        }
        else
        {
            result = new Optional<TWrapper>();
            return false;
        }
    }

    /*static bool TryWrap<TValue>(TValue? value, out Optional<TWrapper> result)
    {
        if (value == null)
        {
            result = new Optional<TWrapper>();
            return true;
        }

        TWrapper innerObj;
        bool success = TWrapper.__TryWrapBypassingCompileTimeValueTypeCheck(value, out innerObj);
        if (success)
        {
            result = new Optional<TWrapper>(innerObj);
            return true;
        }
        else
        {
            result = new Optional<TWrapper>();
            return false;
        }
    }*/

    public Optional()
    {
        nullOrValue = null;
    }

    public Optional(TWrapper nonNullWrapper)
    {
        nullOrValue = nonNullWrapper;
    }

    public bool HasValue { get { return nullOrValue != null; } }
    public TWrapper NonNull { get {
        if (nullOrValue == null)
        {
            throw new NullReferenceException();
        }
        return nullOrValue;
    }}

    public TWrapper? PossiblyNull { get { return nullOrValue; } }
}
