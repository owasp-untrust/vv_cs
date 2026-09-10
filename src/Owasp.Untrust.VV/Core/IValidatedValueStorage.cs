#pragma warning disable CS1591

namespace Owasp.Untrust.VV.Core;

internal interface IValidatedValueStorage<out TValue>
    where TValue : notnull
{
    TValue GetRawValueForInternalUse();
}
