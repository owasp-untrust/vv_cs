#pragma warning disable CS1591

using Owasp.Untrust.ValueDescriptors;

namespace Owasp.Untrust.VV.EntityAccess;

public interface IEntityOperation;

public readonly record struct ScopedSubjectId<TId, TScope>(TId Id, TScope Scope)
    where TId : notnull
    where TScope : notnull;

public interface IAuthenticatedSubject<TId, TScope>
    where TId : notnull
    where TScope : notnull
{
    IReadOnlyCollection<ScopedSubjectId<TId, TScope>> SubjectIds { get; }
}

public interface IEntityRepository<in TId, TEntity>
    where TId : notnull
    where TEntity : notnull
{
    ValueTask<EntityLookupResult<TEntity>> FindByIdAsync(
        TId id,
        CancellationToken cancellationToken = default);
}

public readonly record struct EntityLookupResult<TEntity>
    where TEntity : notnull
{
    private readonly TEntity? _entity;

    private EntityLookupResult(TEntity entity)
    {
        _entity = entity;
        Found = true;
    }

    public bool Found { get; }

    public static EntityLookupResult<TEntity> NotFound => default;

    public static EntityLookupResult<TEntity> FoundEntity(TEntity entity) =>
        new(entity ?? throw new ArgumentNullException(nameof(entity)));

    internal TEntity GetFoundEntity() => Found
        ? _entity!
        : throw new InvalidOperationException("A missing lookup result has no entity.");
}

/// <summary>Returns operation-specific subject grants stored on an entity.</summary>
public interface IEntityAccessGrants<in TEntity, in TOperation, TId, TScope>
    where TEntity : notnull
    where TOperation : IEntityOperation
    where TId : notnull
    where TScope : notnull
{
    IReadOnlyCollection<ScopedSubjectId<TId, TScope>> GetAuthorizedSubjects(
        TEntity entity,
        TOperation operation);
}

public interface IExplicitEntityAuthorizationPolicy<in TEntity, in TSubject, in TOperation>
    where TEntity : notnull
    where TOperation : IEntityOperation
{
    ValueTask<EntityAuthorizationDecision> AuthorizeAsync(
        TSubject subject,
        TEntity entity,
        TOperation operation,
        CancellationToken cancellationToken = default);
}

public readonly record struct EntityAuthorizationDecision
{
    private EntityAuthorizationDecision(bool allowed, string? denialCode)
    {
        Allowed = allowed;
        DenialCode = denialCode;
    }

    public bool Allowed { get; }

    public string? DenialCode { get; }

    public static EntityAuthorizationDecision Allow { get; } = new(true, null);

    public static EntityAuthorizationDecision Deny(Hardcoded denialCode)
    {
        ArgumentNullException.ThrowIfNull(denialCode);
        string code = denialCode.ExposeUnchecked();
        if (string.IsNullOrWhiteSpace(code))
        {
            throw new ArgumentException("A denial code must not be blank.", nameof(denialCode));
        }

        return new EntityAuthorizationDecision(false, code);
    }
}

public interface IAuthorizedEntity
{
    Type EntityType { get; }

    Type OperationType { get; }
}
