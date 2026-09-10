#pragma warning disable CS1591

namespace Owasp.Untrust.VV.Core;

/// <summary>Opaque local-validation evidence that only the VV library can create.</summary>
public sealed class InternallyValidatedValue<TValue, TReceiver>
    where TValue : notnull
{
    internal InternallyValidatedValue(TValue value)
    {
        ValueForReadyConstruction = value;
    }

    public TValue ValueForReadyConstruction { get; }
}
