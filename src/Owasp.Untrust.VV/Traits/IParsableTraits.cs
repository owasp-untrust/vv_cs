using Owasp.Untrust.VV.Core;

namespace Owasp.Untrust.VV.Traits;

/// <summary>Input validation behavior for a non-string value parsed by its own type.</summary>
public interface IParsableTraits<TValue>
    where TValue : notnull, IParsable<TValue>
{
    static abstract TValue NormalizeValue(TValue value);

    static abstract ValidationIssue? ValidateValue(TValue value);
}
