#pragma warning disable CS1591

namespace Owasp.Untrust.VV.Core;

/// <summary>Opaque local-validation evidence that only the VV library can create.</summary>
public sealed class PostValidationRawValue<TValue, TReceiver>
    where TValue : notnull
{
    internal PostValidationRawValue(TValue value)
    {
        ValueForReadyConstruction = value;
    }

    public TValue ValueForReadyConstruction { get; }
}
