using Owasp.Untrust.VV.Core;

namespace Owasp.Untrust.VV.CrossValidation;

/// <summary>Marks a pending value whose next required step is contextual validation.</summary>
public interface IRequiresCrossValidation : IPendingValue;
