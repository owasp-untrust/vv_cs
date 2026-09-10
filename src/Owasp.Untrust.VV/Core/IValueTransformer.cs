#pragma warning disable CS1591

namespace Owasp.Untrust.VV.Core;

/// <summary>Turns a pending primitive into its replacement payload.</summary>
public interface IValueTransformer<in TValue, TOutput>
    where TValue : notnull
    where TOutput : notnull
{
    ValueTask<TOutput> TransformAsync(TValue value, CancellationToken cancellationToken = default);
}
