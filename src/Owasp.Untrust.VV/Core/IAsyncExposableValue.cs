#pragma warning disable CS1591

using Owasp.Untrust.ValueDescriptors.Core;

namespace Owasp.Untrust.VV.Core;

/// <summary>Marks a value whose explicit raw-value boundary is asynchronous.</summary>
public interface IAsyncExposableValue<TValue> : IPubliclyRepresentable
    where TValue : notnull
{
    ValueTask<TValue> ExposeUncheckedAsync(CancellationToken cancellationToken = default);
}
