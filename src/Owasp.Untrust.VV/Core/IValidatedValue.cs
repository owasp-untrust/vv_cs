#pragma warning disable CS1591

using Owasp.Untrust.ValueDescriptors.Core;

namespace Owasp.Untrust.VV.Core;

/// <summary>Non-generic contract used by framework integrations.</summary>
public interface IValidatedValue : IPubliclyRepresentable
{
    /// <summary>The type held by the validated value.</summary>
    Type ValueType { get; }
}

/// <summary>A value whose raw representation passed its complete local pipeline.</summary>
/// <typeparam name="TValue">The protected primitive or framework value.</typeparam>
public interface IValidatedValue<out TValue> : IValidatedValue
    where TValue : notnull;
