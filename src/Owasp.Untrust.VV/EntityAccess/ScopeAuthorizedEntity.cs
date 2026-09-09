#pragma warning disable CS1591

namespace Owasp.Untrust.VV.EntityAccess;

/// <summary>Marker for an authorization scope understood by entity actions.</summary>
public interface IAuthorizationScope;

/// <summary>Immutable runtime set of authorization scope types.</summary>
public sealed class AuthorizationScopeSet : IEquatable<AuthorizationScopeSet>
{
    private readonly HashSet<Type> _scopes;

    private AuthorizationScopeSet(IEnumerable<Type> scopes)
    {
        _scopes = new HashSet<Type>(scopes);
        if (_scopes.Any(static scope => !typeof(IAuthorizationScope).IsAssignableFrom(scope)))
        {
            throw new ArgumentException("Every authorization scope must implement IAuthorizationScope.", nameof(scopes));
        }
    }

    public static AuthorizationScopeSet Empty { get; } = new(Array.Empty<Type>());

    public static AuthorizationScopeSet Of<TFirst>() where TFirst : IAuthorizationScope =>
        new([typeof(TFirst)]);

    public static AuthorizationScopeSet Of<TFirst, TSecond>()
        where TFirst : IAuthorizationScope
        where TSecond : IAuthorizationScope => new([typeof(TFirst), typeof(TSecond)]);

    public static AuthorizationScopeSet Of<TFirst, TSecond, TThird>()
        where TFirst : IAuthorizationScope
        where TSecond : IAuthorizationScope
        where TThird : IAuthorizationScope => new([typeof(TFirst), typeof(TSecond), typeof(TThird)]);

    public bool ContainsAll(AuthorizationScopeSet required) =>
        required is not null && required._scopes.All(_scopes.Contains);

    public bool Equals(AuthorizationScopeSet? other) =>
        other is not null && _scopes.SetEquals(other._scopes);

    public override bool Equals(object? obj) => obj is AuthorizationScopeSet other && Equals(other);

    public override int GetHashCode() => _scopes.Aggregate(0, static (hash, scope) => HashCode.Combine(hash, scope));
}

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

public sealed class EntityAccessQuery
{
    public required AuthorizationScopeSet RequestedScopes { get; init; }

    public required EntityRelationshipRequirementSet RequiredRelationships { get; init; }
}

public sealed class OwnershipProof
{
    internal OwnershipProof() { }
}

public sealed class EntityRelationshipProof
{
    internal EntityRelationshipProof(EntityRelationshipRequirement relationship) => Relationship = relationship;

    public EntityRelationshipRequirement Relationship { get; }
}

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

public interface IEntityAccessRepository<in TId, TEntity, in TSubject>
    where TId : notnull
    where TEntity : notnull
    where TSubject : notnull
{
    ValueTask<EntityAccessLookupResult<TEntity>> LoadForAccessAsync(
        TId id,
        TSubject subject,
        EntityAccessQuery query,
        CancellationToken cancellationToken = default);
}

public interface IAuthorizationVerifier<TEntity, in TSubject>
    where TEntity : notnull
    where TSubject : notnull
{
    ValueTask<AuthorizationScopeSet> VerifyAsync(
        EntityAccessLookupResult<TEntity> lookup,
        TSubject subject,
        EntityAccessQuery query,
        CancellationToken cancellationToken = default);
}

public interface IEntityAction<TSelf, TEntity, TResult>
    where TSelf : IEntityAction<TSelf, TEntity, TResult>
    where TEntity : notnull
{
    static abstract AuthorizationScopeSet RequiredScopes { get; }

    ValueTask<TResult> ExecuteAsync(TEntity entity, CancellationToken cancellationToken = default);
}

/// <summary>Authorization evidence that keeps its entity private behind typed actions.</summary>
public sealed class AuthorizedEntity<TEntity>
    where TEntity : notnull
{
    private readonly TEntity _entity;
    private readonly AuthorizationScopeSet _grantedScopes;

    internal AuthorizedEntity(TEntity entity, AuthorizationScopeSet grantedScopes)
    {
        _entity = entity ?? throw new ArgumentNullException(nameof(entity));
        _grantedScopes = grantedScopes ?? throw new ArgumentNullException(nameof(grantedScopes));
    }

    public async ValueTask<TResult> ExecuteAsync<TAction, TResult>(
        TAction action,
        CancellationToken cancellationToken = default)
        where TAction : IEntityAction<TAction, TEntity, TResult>
    {
        ArgumentNullException.ThrowIfNull(action);
        if (!_grantedScopes.ContainsAll(TAction.RequiredScopes))
        {
            throw new UnauthorizedAccessException("The entity is not authorized for the action's required scopes.");
        }

        cancellationToken.ThrowIfCancellationRequested();
        return await action.ExecuteAsync(_entity, cancellationToken).ConfigureAwait(false);
    }
}
