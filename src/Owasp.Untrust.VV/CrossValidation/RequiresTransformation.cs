using Owasp.Untrust.VV.Core;

namespace Owasp.Untrust.VV.CrossValidation;

/// <summary>Marks a pending value whose next required step replaces its payload.</summary>
public interface IRequiresTransformation : IPendingValue;
