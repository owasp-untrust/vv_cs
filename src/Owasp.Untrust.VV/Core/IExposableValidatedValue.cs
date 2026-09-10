#pragma warning disable CS1591

using Owasp.Untrust.ValueDescriptors.Core;

namespace Owasp.Untrust.VV.Core;

/// <summary>A validated value that explicitly permits raw-value exposure.</summary>
public interface IExposableValidatedValue<out TValue> : IValidatedValue<TValue>, IExposableValue<TValue>
    where TValue : notnull;
