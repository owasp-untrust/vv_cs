#pragma warning disable CS1591

using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Owasp.Untrust.ValueDescriptors.Core;
using Owasp.Untrust.ValueDescriptors.Disclosure;
using Owasp.Untrust.VV.Core;
using Owasp.Untrust.VV.Traits;

namespace Owasp.Untrust.VV.EntityAccess;

public interface IEntityResolutionCandidate : IPubliclyRepresentable
{
    Type EntityIdType { get; }
}

public interface IEntityResolutionCandidateFactory<TSelf, TId>
    where TId : notnull
{
    static abstract TSelf CreateValidated(
        PostValidationRawValue<TId, TSelf> locallyValidatedId);
}

/// <summary>
/// Retains a locally validated entity ID without exposing it. Resolution loads
/// and authorizes the stored entity in one enforced asynchronous transition.
/// </summary>
public abstract class EntityResolutionCandidate<TCandidateSelf, TId, TTraits, TDisclosure> 
    : IEntityResolutionCandidate
    , IParsable<TCandidateSelf>
    where TCandidateSelf : EntityResolutionCandidate<TCandidateSelf, TId, TTraits, TDisclosure>
        , IEntityResolutionCandidateFactory<TCandidateSelf, TId>
    where TId : notnull, IParsable<TId>
    where TTraits : IParsableTraits<TId>
    where TDisclosure : IDisclosurePolicy<TId>
{
    private static ILogger _logger = NullLogger.Instance;
    private readonly TId _locallyValidatedId;

    public static void UseLogger(ILogger logger)
    {
        ArgumentNullException.ThrowIfNull(logger);
        Volatile.Write(ref _logger, logger);
    }

    protected EntityResolutionCandidate(TId locallyValidatedId)
    {
        _locallyValidatedId = locallyValidatedId ?? throw new ArgumentNullException(nameof(locallyValidatedId));
    }

    public Type EntityIdType => typeof(TId);

    public string ToPublicString() => TDisclosure.ToPublicString(_locallyValidatedId);

    public sealed override string ToString() => ToPublicString();

    public async ValueTask<ScopeAuthorizedEntity<TEntity>> AuthorizeAsync<TEntity, TSubject>(
        IEntityAccessRepository<TId, TEntity, TSubject> repository,
        TSubject subject,
        EntityAccessQuery query,
        IAuthorizationVerifier<TEntity, TSubject> authorizationVerifier,
        CancellationToken cancellationToken = default)
        where TEntity : notnull
        where TSubject : notnull
    {
        ArgumentNullException.ThrowIfNull(repository);
        ArgumentNullException.ThrowIfNull(subject);
        ArgumentNullException.ThrowIfNull(query);
        ArgumentNullException.ThrowIfNull(authorizationVerifier);
        cancellationToken.ThrowIfCancellationRequested();

        EntityAccessLookupResult<TEntity> lookup = await repository
            .LoadForAccessAsync(_locallyValidatedId, subject, query, cancellationToken)
            .ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (!lookup.Found)
        {
            throw new UnauthorizedAccessException("The entity was not found or is not accessible.");
        }

        AuthorizationScopeSet grantedScopes = await authorizationVerifier
            .VerifyAsync(lookup, subject, query, cancellationToken)
            .ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (!grantedScopes.ContainsAll(query.RequestedScopes))
        {
            throw new UnauthorizedAccessException("The entity is not authorized for the requested scopes.");
        }

        return new ScopeAuthorizedEntity<TEntity>(lookup.Entity!, grantedScopes);
    }

    public static TCandidateSelf Parse(string text, IFormatProvider? provider)
    {
        TId value = TTraits.NormalizeValue(TId.Parse(text, provider));
        ValidationIssue? issue = TTraits.ValidateValue(value);
        ValidationTests.RequireNoIssue(issue);
        return TCandidateSelf.CreateValidated(new PostValidationRawValue<TId, TCandidateSelf>(value));
    }

    public static bool TryParse(
        string? text,
        IFormatProvider? provider,
        [MaybeNullWhen(false)] out TCandidateSelf result)
    {
        if (TId.TryParse(text, provider, out TId? value))
        {
            try
            {
                value = TTraits.NormalizeValue(value);
                ValidationIssue? issue = TTraits.ValidateValue(value);
                if (issue is null)
                {
                    result = TCandidateSelf.CreateValidated(new PostValidationRawValue<TId, TCandidateSelf>(value));
                    Logger.LogDebug("Entity-resolution candidate parsing succeeded.");
                    return true;
                }
                Logger.LogWarning("Entity-resolution candidate parsing was rejected by validation.");
            }
            catch (ValidationException exception)
            {
                Logger.LogWarning(
                    "Entity-resolution candidate parsing failed with {ExceptionType}.",
                    exception.GetType().Name);
            }
        }
        else
        {
            Logger.LogWarning("Entity-resolution candidate parsing received an invalid identifier format.");
        }

        result = null;
        return false;
    }

    private static ILogger Logger => Volatile.Read(ref _logger);

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
