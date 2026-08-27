#pragma warning disable CS1591

using Owasp.Untrust.ValueDescriptors.Disclosure;
using Owasp.Untrust.ValueDescriptors;
using Owasp.Untrust.VV.Archetypes;
using Owasp.Untrust.VV.Core;
using Owasp.Untrust.VV.EntityAccess;
using Xunit;

namespace Owasp.Untrust.VV.Tests;

public sealed class EntityAccessTests
{
    [Fact]
    public async Task SharedReadGrantCanAuthorizeWhileUpdateGrantDoesNot()
    {
        Document document = new(
            "document-1",
            Readers: [User("alice"), Group("editors")],
            Editors: [User("bob")]);
        RecordingRepository repository = new(document);
        TestSubject alice = new([User("alice"), Group("staff")]);
        DocumentIdCandidate candidate = DocumentIdCandidate.Parse("document-1", null);

        AuthorizedEntity<Document, ReadDocument> readable =
            await candidate.ResolveReadAsync(repository, alice, DocumentGrants.Instance);

        Assert.Same(document, readable.ExposeAuthorizedEntity());
        Assert.Equal(typeof(ReadDocument), readable.OperationType);
        EntityAccessException failure = await Assert.ThrowsAsync<EntityAccessException>(
            async () => await candidate.ResolveUpdateAsync(repository, alice, DocumentGrants.Instance));
        Assert.Equal(EntityAccessFailureKind.NotFound, failure.FailureKind);
        Assert.Equal(2, repository.CallCount);
    }

    [Fact]
    public async Task AGrantMatchesOnlyWhenBothIdAndScopeMatch()
    {
        Document document = new("document-1", Readers: [Group("shared")], Editors: []);
        DocumentIdCandidate candidate = DocumentIdCandidate.Parse("document-1", null);

        EntityAccessException failure = await Assert.ThrowsAsync<EntityAccessException>(
            async () => await candidate.ResolveReadAsync(
                new RecordingRepository(document),
                new TestSubject([User("shared")]),
                DocumentGrants.Instance));

        Assert.Equal("entity.not_found", failure.ErrorCode);
    }

    [Fact]
    public async Task HiddenPolicyMakesMissingAndForbiddenIndistinguishableAndLeakFree()
    {
        const string sensitiveId = "secret-document";
        DocumentIdCandidate candidate = DocumentIdCandidate.Parse(sensitiveId, null);
        TestSubject stranger = new([User("mallory")]);

        EntityAccessException missing = await Assert.ThrowsAsync<EntityAccessException>(
            async () => await candidate.ResolveReadAsync(
                new RecordingRepository(entity: null), stranger, DocumentGrants.Instance));
        EntityAccessException forbidden = await Assert.ThrowsAsync<EntityAccessException>(
            async () => await candidate.ResolveReadAsync(
                new RecordingRepository(new Document(sensitiveId, [User("alice")], [])),
                stranger,
                DocumentGrants.Instance));

        Assert.Equal(missing.ErrorCode, forbidden.ErrorCode);
        Assert.Equal(missing.Message, forbidden.Message);
        Assert.DoesNotContain(sensitiveId, missing.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(sensitiveId, forbidden.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("mallory", forbidden.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task ExplicitDisclosureCanDistinguishForbidden()
    {
        Document document = new("document-1", [User("alice")], []);
        DocumentIdCandidate candidate = DocumentIdCandidate.Parse("document-1", null);

        EntityAccessException failure = await Assert.ThrowsAsync<EntityAccessException>(
            async () => await candidate.ResolveReadWithForbiddenDisclosureAsync(
                new RecordingRepository(document),
                new TestSubject([User("mallory")]),
                DocumentGrants.Instance));

        Assert.Equal(EntityAccessFailureKind.Forbidden, failure.FailureKind);
        Assert.Equal("entity.forbidden", failure.ErrorCode);
    }

    [Fact]
    public async Task RepositoryReceivesLocallyValidatedIdExactlyOnce()
    {
        Document document = new("document-1", [User("alice")], []);
        RecordingRepository repository = new(document);
        DocumentIdCandidate candidate = DocumentIdCandidate.Parse("  DOCUMENT-1  ", null);

        await candidate.ResolveReadAsync(
            repository,
            new TestSubject([User("alice")]),
            DocumentGrants.Instance);

        Assert.Equal(1, repository.CallCount);
        Assert.Equal("document-1", repository.LastId);
    }

    [Fact]
    public async Task CancellationPreventsLookupAndEvidenceCreation()
    {
        DocumentIdCandidate candidate = DocumentIdCandidate.Parse("document-1", null);
        RecordingRepository repository = new(new Document("document-1", [User("alice")], []));
        using CancellationTokenSource source = new();
        source.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await candidate.ResolveReadAsync(
                repository,
                new TestSubject([User("alice")]),
                DocumentGrants.Instance,
                source.Token));

        Assert.Equal(0, repository.CallCount);
    }

    [Fact]
    public void CandidateAndEvidenceCannotBePubliclyConstructedOrExposeTheId()
    {
        DocumentIdCandidate candidate = DocumentIdCandidate.Parse("document-1", null);

        Assert.IsAssignableFrom<IEntityResolutionCandidate>(candidate);
        Assert.False((object)candidate is IValidatedValue);
        Assert.Null(candidate.GetType().GetMethod("ExposeUnchecked"));
        Assert.Empty(typeof(AuthorizedEntity<Document, ReadDocument>).GetConstructors());
    }

    [Fact]
    public async Task ExplicitPolicyPathIsSeparateAndCarriesOnlySafeDenialCode()
    {
        const string entityText = "private-document";
        Document document = new(entityText, [], []);
        DocumentIdCandidate candidate = DocumentIdCandidate.Parse(entityText, null);

        EntityAccessException failure = await Assert.ThrowsAsync<EntityAccessException>(
            async () => await candidate.ResolveWithPolicyAsync(
                new RecordingRepository(document),
                new TestSubject([User("alice")]),
                DenyPolicy.Instance));

        Assert.Equal("document.archived", failure.InternalDenialCode);
        Assert.DoesNotContain(entityText, failure.ToString(), StringComparison.Ordinal);
    }

    private static ScopedSubjectId<string, IdentityScope> User(string id) =>
        new(id, IdentityScope.User);

    private static ScopedSubjectId<string, IdentityScope> Group(string id) =>
        new(id, IdentityScope.Group);

    private enum IdentityScope
    {
        User,
        Group
    }

    private sealed record Document(
        string Id,
        IReadOnlyCollection<ScopedSubjectId<string, IdentityScope>> Readers,
        IReadOnlyCollection<ScopedSubjectId<string, IdentityScope>> Editors);

    private sealed class ReadDocument : IEntityOperation
    {
        public static ReadDocument Instance { get; } = new();
        private ReadDocument() { }
    }

    private sealed class UpdateDocument : IEntityOperation
    {
        public static UpdateDocument Instance { get; } = new();
        private UpdateDocument() { }
    }

    private sealed class TestSubject(
        IReadOnlyCollection<ScopedSubjectId<string, IdentityScope>> subjectIds) :
        IAuthenticatedSubject<string, IdentityScope>
    {
        public IReadOnlyCollection<ScopedSubjectId<string, IdentityScope>> SubjectIds { get; } = subjectIds;
    }

    private sealed class DocumentGrants :
        IEntityAccessGrants<Document, ReadDocument, string, IdentityScope>,
        IEntityAccessGrants<Document, UpdateDocument, string, IdentityScope>
    {
        public static DocumentGrants Instance { get; } = new();
        private DocumentGrants() { }

        public IReadOnlyCollection<ScopedSubjectId<string, IdentityScope>> GetAuthorizedSubjects(
            Document entity,
            ReadDocument operation) => entity.Readers;

        public IReadOnlyCollection<ScopedSubjectId<string, IdentityScope>> GetAuthorizedSubjects(
            Document entity,
            UpdateDocument operation) => entity.Editors;
    }

    private sealed class RecordingRepository(Document? entity) : IEntityRepository<string, Document>
    {
        public int CallCount { get; private set; }
        public string? LastId { get; private set; }

        public ValueTask<EntityLookupResult<Document>> FindByIdAsync(
            string id,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            CallCount++;
            LastId = id;
            return ValueTask.FromResult(entity is null
                ? EntityLookupResult<Document>.NotFound
                : EntityLookupResult<Document>.FoundEntity(entity));
        }
    }

    private sealed class DenyPolicy :
        IExplicitEntityAuthorizationPolicy<Document, TestSubject, ReadDocument>
    {
        public static DenyPolicy Instance { get; } = new();
        private DenyPolicy() { }

        public ValueTask<EntityAuthorizationDecision> AuthorizeAsync(
            TestSubject subject,
            Document entity,
            ReadDocument operation,
            CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(EntityAuthorizationDecision.Deny(
                Hardcoded.From("document.archived")));
    }

    private sealed class DocumentIdTraits :
        IBoundedStringTraits<DocumentIdTraits, Public<string>>
    {
        public static Bounds<int> LengthBounds => new(1, 64);

        public static bool TryParse(
            string raw,
            IFormatProvider? provider,
            out string value)
        {
            value = raw;
            return true;
        }

        public static string Normalize(string value) => value.Trim().ToLowerInvariant();

        public static ValidationIssue? ValidateAdditional(string normalized) => null;
    }

    private sealed class DocumentIdCandidate :
        EntityResolutionCandidate<
            DocumentIdCandidate,
            string,
            DocumentIdTraits,
            BoundedStringArchetype<DocumentIdTraits, Public<string>>,
            Public<string>>,
        IEntityResolutionCandidateFactory<DocumentIdCandidate, string>
    {
        private DocumentIdCandidate(string id) : base(id) { }

        static DocumentIdCandidate
            IEntityResolutionCandidateFactory<DocumentIdCandidate, string>.CreateValidated(string id) =>
            new(id);

        public ValueTask<AuthorizedEntity<Document, ReadDocument>> ResolveReadAsync(
            IEntityRepository<string, Document> repository,
            IAuthenticatedSubject<string, IdentityScope> subject,
            IEntityAccessGrants<Document, ReadDocument, string, IdentityScope> grants,
            CancellationToken cancellationToken = default) =>
            ResolveAnyGrantAsync<Document, ReadDocument, string, IdentityScope, HideEntityExistence>(
                repository, subject, grants, ReadDocument.Instance, cancellationToken);

        public ValueTask<AuthorizedEntity<Document, UpdateDocument>> ResolveUpdateAsync(
            IEntityRepository<string, Document> repository,
            IAuthenticatedSubject<string, IdentityScope> subject,
            IEntityAccessGrants<Document, UpdateDocument, string, IdentityScope> grants,
            CancellationToken cancellationToken = default) =>
            ResolveAnyGrantAsync<Document, UpdateDocument, string, IdentityScope, HideEntityExistence>(
                repository, subject, grants, UpdateDocument.Instance, cancellationToken);

        public ValueTask<AuthorizedEntity<Document, ReadDocument>> ResolveReadWithForbiddenDisclosureAsync(
            IEntityRepository<string, Document> repository,
            IAuthenticatedSubject<string, IdentityScope> subject,
            IEntityAccessGrants<Document, ReadDocument, string, IdentityScope> grants,
            CancellationToken cancellationToken = default) =>
            ResolveAnyGrantAsync<Document, ReadDocument, string, IdentityScope, RevealEntityForbidden>(
                repository, subject, grants, ReadDocument.Instance, cancellationToken);

        public ValueTask<AuthorizedEntity<Document, ReadDocument>> ResolveWithPolicyAsync(
            IEntityRepository<string, Document> repository,
            TestSubject subject,
            IExplicitEntityAuthorizationPolicy<Document, TestSubject, ReadDocument> policy,
            CancellationToken cancellationToken = default) =>
            ResolveUsingExplicitAuthorizationPolicyAsync<Document, ReadDocument, TestSubject, HideEntityExistence>(
                repository, subject, policy, ReadDocument.Instance, cancellationToken);
    }
}
