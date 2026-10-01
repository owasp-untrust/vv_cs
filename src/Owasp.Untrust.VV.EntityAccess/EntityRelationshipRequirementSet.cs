#pragma warning disable CS1591

namespace Owasp.Untrust.VV.EntityAccess;

public enum EntityRelationshipRequirement
{
    Owner,
    SharedReader,
    SharedEditor,
}

public sealed class EntityRelationshipRequirementSet
{
    private readonly HashSet<EntityRelationshipRequirement> _requirements;

    private EntityRelationshipRequirementSet(IEnumerable<EntityRelationshipRequirement> requirements) =>
        _requirements = new HashSet<EntityRelationshipRequirement>(requirements);

    public static EntityRelationshipRequirementSet AnyOf(
        params EntityRelationshipRequirement[] requirements) => new(requirements);

    public bool Contains(EntityRelationshipRequirement requirement) => _requirements.Contains(requirement);
}
