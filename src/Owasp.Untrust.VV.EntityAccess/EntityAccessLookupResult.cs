#pragma warning disable CS1591

namespace Owasp.Untrust.VV.EntityAccess;

public sealed class EntityAccessLookupResult<TEntity>
    where TEntity : notnull
{
    private EntityAccessLookupResult() { }

    private EntityAccessLookupResult(
        TEntity entity,
        OwnershipProof? ownership,
        IReadOnlyCollection<EntityRelationshipProof> relationships,
        AuthorizationScopeSet grantedScopes)
    {
        Entity = entity;
        Ownership = ownership;
        Relationships = relationships;
        GrantedScopes = grantedScopes;
        Found = true;
    }

    public bool Found { get; }

    internal TEntity? Entity { get; }

    public OwnershipProof? Ownership { get; }

    public IReadOnlyCollection<EntityRelationshipProof>? Relationships { get; }

    public AuthorizationScopeSet? GrantedScopes { get; }

    public static EntityAccessLookupResult<TEntity> NotFound { get; } = new();

    public static EntityAccessLookupResult<TEntity> FoundEntity(
        TEntity entity,
        OwnershipProof? ownership,
        IReadOnlyCollection<EntityRelationshipProof> relationships,
        AuthorizationScopeSet grantedScopes) => new(
            entity ?? throw new ArgumentNullException(nameof(entity)),
            ownership,
            relationships ?? throw new ArgumentNullException(nameof(relationships)),
            grantedScopes ?? throw new ArgumentNullException(nameof(grantedScopes)));
}
