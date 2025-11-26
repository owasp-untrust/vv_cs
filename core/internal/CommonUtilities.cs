using Owasp.Untrust.VV.Core;

namespace Owasp.Untrust.VV.Internal;

internal static class CommonUtilities
{
    public static Type? FindValidatedValueBase(Type t)
    {
        while (t is not null)
        {
            if (t.IsGenericType &&
                t.GetGenericTypeDefinition() == typeof(ValidatedValue<,,>))
            {
                return t;
            }

            t = t.BaseType!;
        }

        return null;
    }

    public static bool IsOptional(Type t) {
        return (t.IsGenericType &&
            t.GetGenericTypeDefinition() == typeof(Optional<>));
    }

    public static Type? TryExtractOptionalInternalType(Type possiblyOptionalType)
    {
        if (!IsOptional(possiblyOptionalType))
        {
            return null;
        }

        var wrapperType = possiblyOptionalType.GetGenericArguments()[0];
        return FindValidatedValueBase(wrapperType);
    }
}