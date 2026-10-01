#pragma warning disable CS1591

namespace Owasp.Untrust.VV.EntityAccess;

public sealed class EntityAccessQuery
{
    public required AuthorizationScopeSet RequestedScopes { get; init; }

    public required EntityRelationshipRequirementSet RequiredRelationships { get; init; }
}
