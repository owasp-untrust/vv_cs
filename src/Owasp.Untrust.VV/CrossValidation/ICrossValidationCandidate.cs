#pragma warning disable CS1591
using Owasp.Untrust.ValueDescriptors.Core;

namespace Owasp.Untrust.VV.CrossValidation;

/// <summary>
/// Marks a locally validated candidate that still requires contextual validation.
/// ASP.NET integration uses this marker to reject response serialization.
/// </summary>
public interface ICrossValidationCandidate : IPubliclyRepresentable
{
    Type ReceiverType { get; }
}
