#pragma warning disable CS1591

using System.Diagnostics.CodeAnalysis;
using Owasp.Untrust.ValueDescriptors.Core;
using Owasp.Untrust.ValueDescriptors.Disclosure;
using Owasp.Untrust.VV.Core;

namespace Owasp.Untrust.VV.EntityAccess;

public interface IEntityResolutionCandidate : IPubliclyRepresentable
{
    Type EntityIdType { get; }
}

public interface IEntityResolutionCandidateFactory<TSelf, TId>
    where TId : notnull
{
    static abstract TSelf CreateValidated(TId locallyValidatedId);
}

/// <summary>
/// Retains a locally validated entity ID without exposing it. Resolution loads
/// and authorizes the stored entity in one enforced asynchronous transition.
/// </summary>
public abstract class EntityResolutionCandidate<
    TCandidate,
    TId,
    TTraits,
    TArchetype,
    TDisclosure> : IEntityResolutionCandidate, IParsable<TCandidate>
    where TCandidate : EntityResolutionCandidate<TCandidate, TId, TTraits, TArchetype, TDisclosure>,
        IEntityResolutionCandidateFactory<TCandidate, TId>
    where TId : notnull
    where TTraits : IValidationTraits<TId, TDisclosure>
    where TArchetype : IValidationArchetype<TId>
    where TDisclosure : IDisclosurePolicy<TId>
{
    private readonly TId _locallyValidatedId;

    protected EntityResolutionCandidate(TId locallyValidatedId)
    {
        _locallyValidatedId = locallyValidatedId ?? throw new ArgumentNullException(nameof(locallyValidatedId));
    }

    public Type EntityIdType => typeof(TId);

    public object? ToPublicValue() => TDisclosure.ToPublicValue(_locallyValidatedId);

    public string ToPublicString() => TDisclosure.ToPublicString(_locallyValidatedId);

    public sealed override string ToString() => ToPublicString();

    public static TCandidate Parse(string text, IFormatProvider? provider)
    {
        TId validated = ValidationTraitsPipeline.Run<TId, TTraits, TArchetype, TDisclosure>(text, provider);
        return TCandidate.CreateValidated(validated);
    }

    public static bool TryParse(
        string? text,
        IFormatProvider? provider,
        [NotNullWhen(true)] out TCandidate? result)
    {
        if (ValidationTraitsPipeline.TryRun<TId, TTraits, TArchetype, TDisclosure>(
                text,
                provider,
                out TId? validated))
        {
            result = TCandidate.CreateValidated(validated);
            return true;
        }

        result = null;
        return false;
    }

    protected ValueTask<AuthorizedEntity<TEntity, TOperation>> ResolveAnyGrantAsync<
        TEntity,
        TOperation,
        TSubjectId,
        TScope,
        TFailureDisclosure>(
        IEntityRepository<TId, TEntity> repository,
        IAuthenticatedSubject<TSubjectId, TScope> subject,
        IEntityAccessGrants<TEntity, TOperation, TSubjectId, TScope> grants,
        TOperation operation,
        CancellationToken cancellationToken = default)
        where TEntity : notnull
        where TOperation : IEntityOperation
        where TSubjectId : notnull
        where TScope : notnull
        where TFailureDisclosure : IEntityAccessFailureDisclosure
    {
        ArgumentNullException.ThrowIfNull(repository);
        ArgumentNullException.ThrowIfNull(subject);
        ArgumentNullException.ThrowIfNull(grants);
        ArgumentNullException.ThrowIfNull(operation);

        return ResolveAnyGrantCoreAsync<TEntity, TOperation, TSubjectId, TScope, TFailureDisclosure>(
            repository,
            subject,
            grants,
            operation,
            cancellationToken);
    }

    protected ValueTask<AuthorizedEntity<TEntity, TOperation>>
        ResolveUsingExplicitAuthorizationPolicyAsync<
            TEntity,
            TOperation,
            TSubject,
            TFailureDisclosure>(
            IEntityRepository<TId, TEntity> repository,
            TSubject subject,
            IExplicitEntityAuthorizationPolicy<TEntity, TSubject, TOperation> policy,
            TOperation operation,
            CancellationToken cancellationToken = default)
        where TEntity : notnull
        where TOperation : IEntityOperation
        where TSubject : notnull
        where TFailureDisclosure : IEntityAccessFailureDisclosure
    {
        ArgumentNullException.ThrowIfNull(repository);
        ArgumentNullException.ThrowIfNull(subject);
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(operation);

        return ResolveExplicitPolicyCoreAsync<TEntity, TOperation, TSubject, TFailureDisclosure>(
            repository,
            subject,
            policy,
            operation,
            cancellationToken);
    }

    private async ValueTask<AuthorizedEntity<TEntity, TOperation>> ResolveAnyGrantCoreAsync<
        TEntity,
        TOperation,
        TSubjectId,
        TScope,
        TFailureDisclosure>(
        IEntityRepository<TId, TEntity> repository,
        IAuthenticatedSubject<TSubjectId, TScope> subject,
        IEntityAccessGrants<TEntity, TOperation, TSubjectId, TScope> grants,
        TOperation operation,
        CancellationToken cancellationToken)
        where TEntity : notnull
        where TOperation : IEntityOperation
        where TSubjectId : notnull
        where TScope : notnull
        where TFailureDisclosure : IEntityAccessFailureDisclosure
    {
        TEntity entity = await LoadEntityAsync<TEntity, TFailureDisclosure>(repository, cancellationToken)
            .ConfigureAwait(false);

        cancellationToken.ThrowIfCancellationRequested();
        IReadOnlyCollection<ScopedSubjectId<TSubjectId, TScope>> subjectIds =
            subject.SubjectIds ?? throw new InvalidOperationException("An authenticated subject returned null identities.");
        IReadOnlyCollection<ScopedSubjectId<TSubjectId, TScope>> authorizedSubjects =
            grants.GetAuthorizedSubjects(entity, operation) ??
            throw new InvalidOperationException("An entity grant provider returned null grants.");

        HashSet<ScopedSubjectId<TSubjectId, TScope>> heldIds = new(subjectIds);
        if (!authorizedSubjects.Any(heldIds.Contains))
        {
            throw new EntityAccessException(TFailureDisclosure.UnauthorizedEntity);
        }

        cancellationToken.ThrowIfCancellationRequested();
        return new AuthorizedEntity<TEntity, TOperation>(entity);
    }

    private async ValueTask<AuthorizedEntity<TEntity, TOperation>> ResolveExplicitPolicyCoreAsync<
        TEntity,
        TOperation,
        TSubject,
        TFailureDisclosure>(
        IEntityRepository<TId, TEntity> repository,
        TSubject subject,
        IExplicitEntityAuthorizationPolicy<TEntity, TSubject, TOperation> policy,
        TOperation operation,
        CancellationToken cancellationToken)
        where TEntity : notnull
        where TOperation : IEntityOperation
        where TSubject : notnull
        where TFailureDisclosure : IEntityAccessFailureDisclosure
    {
        TEntity entity = await LoadEntityAsync<TEntity, TFailureDisclosure>(repository, cancellationToken)
            .ConfigureAwait(false);

        cancellationToken.ThrowIfCancellationRequested();
        EntityAuthorizationDecision decision = await policy.AuthorizeAsync(
                subject,
                entity,
                operation,
                cancellationToken)
            .ConfigureAwait(false);

        if (!decision.Allowed)
        {
            throw new EntityAccessException(
                TFailureDisclosure.UnauthorizedEntity,
                decision.DenialCode);
        }

        cancellationToken.ThrowIfCancellationRequested();
        return new AuthorizedEntity<TEntity, TOperation>(entity);
    }

    private async ValueTask<TEntity> LoadEntityAsync<TEntity, TFailureDisclosure>(
        IEntityRepository<TId, TEntity> repository,
        CancellationToken cancellationToken)
        where TEntity : notnull
        where TFailureDisclosure : IEntityAccessFailureDisclosure
    {
        cancellationToken.ThrowIfCancellationRequested();
        EntityLookupResult<TEntity> lookup = await repository.FindByIdAsync(
                _locallyValidatedId,
                cancellationToken)
            .ConfigureAwait(false);

        cancellationToken.ThrowIfCancellationRequested();
        if (!lookup.Found)
        {
            throw new EntityAccessException(TFailureDisclosure.MissingEntity);
        }

        return lookup.GetFoundEntity();
    }
}

