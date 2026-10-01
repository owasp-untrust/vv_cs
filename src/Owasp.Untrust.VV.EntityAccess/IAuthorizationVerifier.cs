#pragma warning disable CS1591

namespace Owasp.Untrust.VV.EntityAccess;

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
