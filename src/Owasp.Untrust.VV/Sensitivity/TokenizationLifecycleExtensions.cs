#pragma warning disable CS1591
using Owasp.Untrust.VV.Core;

namespace Owasp.Untrust.VV.Sensitivity;

public static class TokenizationLifecycleExtensions
{
    public static PendingTokenization<TValue> PendingTokenization<TValue>(
        this IValidatedValue<TValue> source)
        where TValue : notnull => new(source);
}
