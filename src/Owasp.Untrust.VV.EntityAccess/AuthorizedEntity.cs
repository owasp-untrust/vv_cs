#pragma warning disable CS1591

namespace Owasp.Untrust.VV.EntityAccess;

public sealed class AuthorizedEntity<TEntity, TOperation> : IAuthorizedEntity
    where TEntity : notnull
    where TOperation : IEntityOperation
{
    private readonly TEntity _entity;

    internal AuthorizedEntity(TEntity entity)
    {
        _entity = entity ?? throw new ArgumentNullException(nameof(entity));
    }

    public Type EntityType => typeof(TEntity);

    public Type OperationType => typeof(TOperation);

    public TEntity ExposeAuthorizedEntity() => _entity;
}

