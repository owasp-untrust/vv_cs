#pragma warning disable CS1591
using System.Diagnostics.CodeAnalysis;
using Owasp.Untrust.VV.Core;
using Owasp.Untrust.ValueDescriptors.Disclosure;

namespace Owasp.Untrust.VV.CrossValidation;

/// <summary>Library-only construction hook implemented explicitly by a candidate leaf.</summary>
public interface ICrossValidationCandidateFactory<TSelf, TValue>
    where TValue : notnull
{
    static abstract TSelf CreateValidated(
        PostValidationRawValue<TValue, TSelf> locallyValidatedValue);
}
