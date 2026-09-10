#pragma warning disable CS1591

using Owasp.Untrust.ValueDescriptors.Core;

namespace Owasp.Untrust.VV.Core;

/// <summary>Marks a locally valid value that requires a further transition.</summary>
public interface IPendingValue : IPubliclyRepresentable;
