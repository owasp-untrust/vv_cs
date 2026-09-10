#pragma warning disable CS1591

namespace Owasp.Untrust.VV.Core;

/// <summary>Opaque transformation evidence emitted only after a transform succeeds.</summary>
public sealed class InternallyTransformedValue<TOutput, TReceiver>
    where TOutput : notnull
{
    internal InternallyTransformedValue(TOutput value)
    {
        ValueForReadyConstruction = value;
    }

    public TOutput ValueForReadyConstruction { get; }
}
