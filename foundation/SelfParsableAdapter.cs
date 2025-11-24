using System.Diagnostics.CodeAnalysis;

namespace Owasp.Untrust.VV.Foundation;

public class SelfParsableAdapter<TValue> : IQueryParsable<TValue>
where TValue : IParsable<TValue>
{
    public static bool TryParse([NotNullWhen(true)] string? s, IFormatProvider? provider, [MaybeNullWhen(false)] out TValue result)
    {
        return TValue.TryParse(s, provider, out result);
    }
}
