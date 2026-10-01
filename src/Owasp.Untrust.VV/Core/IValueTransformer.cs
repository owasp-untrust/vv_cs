#pragma warning disable CS1591

namespace Owasp.Untrust.VV.Core;

/// <summary>Turns a pending primitive into its replacement payload.</summary>
public interface IValueTransformer<in TValue, TTransformedVal>
    where TValue : notnull
    where TTransformedVal : notnull
{
    ValueTask<TTransformedVal> TransformAsync(TValue value, CancellationToken cancellationToken = default);
}
