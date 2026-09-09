#pragma warning disable CS1591

using Owasp.Untrust.ValueDescriptors.Core;

namespace Owasp.Untrust.VV.Core;

/// <summary>Non-generic contract used by framework integrations.</summary>
public interface IValidatedValue : IPubliclyRepresentable
{
    /// <summary>The type held by the validated value.</summary>
    Type ValueType { get; }
}

internal interface IValidatedValueStorage<out TValue>
    where TValue : notnull
{
    TValue GetRawValueForInternalUse();
}

/// <summary>A value whose raw representation passed its complete local pipeline.</summary>
/// <typeparam name="TValue">The protected primitive or framework value.</typeparam>
public interface IValidatedValue<out TValue> : IValidatedValue
    where TValue : notnull
{ }

/// <summary>A validated value that explicitly permits raw-value exposure.</summary>
public interface IExposableValidatedValue<out TValue> :
    IValidatedValue<TValue>,
    IExposableValue<TValue>
    where TValue : notnull;
