using System.Diagnostics.CodeAnalysis;

namespace Owasp.Untrust.VV.Foundation;

public class NotQueryParsable<TValue> : IQueryParsable<TValue>
{
    public static bool TryParse([NotNullWhen(true)] string? s, IFormatProvider? provider, [MaybeNullWhen(false)] out TValue result)
    {
        result = default;
        return false;
    }
}
