#pragma warning disable CS1591

namespace Owasp.Untrust.VV.EntityAccess;

/// <summary>Authorization evidence for a set of scopes, used with typed actions.</summary>
public sealed class ScopeAuthorizedEntity<TEntity>
    where TEntity : notnull
{
    private readonly TEntity _entity;
    private readonly AuthorizationScopeSet _grantedScopes;

    internal ScopeAuthorizedEntity(TEntity entity, AuthorizationScopeSet grantedScopes)
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
