#pragma warning disable CS1591
using Owasp.Untrust.VV.Core;

namespace Owasp.Untrust.VV.CrossValidation;

/// <summary>
/// Marks a value whose contextual validation has completed. ASP.NET integration
/// uses this marker to reject direct request deserialization.
/// </summary>
public interface ICrossValidatedValue : IValidatedValue;
