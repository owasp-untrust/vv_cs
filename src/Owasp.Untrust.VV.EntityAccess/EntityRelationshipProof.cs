#pragma warning disable CS1591

namespace Owasp.Untrust.VV.EntityAccess;

public sealed class EntityRelationshipProof
{
    internal EntityRelationshipProof(EntityRelationshipRequirement relationship) => Relationship = relationship;

    public EntityRelationshipRequirement Relationship { get; }
}
