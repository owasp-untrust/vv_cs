#pragma warning disable CS1591

namespace Owasp.Untrust.VV.EntityAccess;

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
