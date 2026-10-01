#pragma warning disable CS1591

namespace Owasp.Untrust.VV.EntityAccess;

public interface IEntityAction<TSelf, TEntity, TResult>
    where TSelf : IEntityAction<TSelf, TEntity, TResult>
    where TEntity : notnull
{
    static abstract AuthorizationScopeSet RequiredScopes { get; }

    ValueTask<TResult> ExecuteAsync(TEntity entity, CancellationToken cancellationToken = default);
}
