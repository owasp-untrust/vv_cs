#pragma warning disable CS1591

namespace Owasp.Untrust.VV.Core;

/// <summary>Opaque transformation evidence emitted only after a transform succeeds.</summary>
public sealed class InternallyTransformedValue<TSelf, TTransformedVal>
    where TTransformedVal : notnull
{
    internal InternallyTransformedValue(TTransformedVal value)
    {
        ValueForReadyConstruction = value;
    }

    public TTransformedVal ValueForReadyConstruction { get; }
}
