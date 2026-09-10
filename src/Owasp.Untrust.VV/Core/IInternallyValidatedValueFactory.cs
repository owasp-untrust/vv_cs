#pragma warning disable CS1591

namespace Owasp.Untrust.VV.Core;

public interface IInternallyValidatedValueFactory<TSelf, TValue>
    where TValue : notnull
{
    static abstract TSelf CreateValidated(InternallyValidatedValue<TValue, TSelf> validated);
}
