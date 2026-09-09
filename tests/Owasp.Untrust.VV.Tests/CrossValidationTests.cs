#pragma warning disable CS1591
using Xunit;
using Owasp.Untrust.VV.Core;
using Owasp.Untrust.VV.CrossValidation;
using Owasp.Untrust.ValueDescriptors.Disclosure;

namespace Owasp.Untrust.VV.Tests;

public sealed class CrossValidationTests
{
    [Fact]
    public async Task ParsingPerformsOnlyLocalValidation()
    {
        ExistingEmailCandidate candidate = ExistingEmailCandidate.Parse(
            "alice@example.com",
            null);
        RecordingDirectory directory = new(exists: true);

        Assert.Equal(0, directory.CallCount);

        ExistingEmail receiver = await candidate.ConfirmExistsAsync(directory);

        Assert.Equal(1, directory.CallCount);
        Assert.Equal("alice@example.com", receiver.ExposeUnchecked());
    }

    [Fact]
    public async Task FailedCrossValidationCannotProduceReceiverAndDoesNotLeakInput()
    {
        const string input = "missing@example.com";
        ExistingEmailCandidate candidate = ExistingEmailCandidate.Parse(input, null);

        CrossValidationException failure = await Assert.ThrowsAsync<CrossValidationException>(
            async () => await candidate.ConfirmExistsAsync(new RecordingDirectory(exists: false)));

        Assert.Equal("email.not_found", failure.ErrorCode);
        Assert.DoesNotContain(input, failure.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task CancellationCannotMintCompletion()
    {
        ExistingEmailCandidate candidate = ExistingEmailCandidate.Parse(
            "alice@example.com",
            null);
        CancellationTokenSource source = new();
        source.Cancel();
        RecordingDirectory directory = new(exists: true);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await candidate.ConfirmExistsAsync(directory, source.Token));

        Assert.Equal(0, directory.CallCount);
    }

    [Fact]
    public void CandidateHasNoRawEscapeHatchAndCompletionCannotBePubliclyConstructed()
    {
        ExistingEmailCandidate candidate = ExistingEmailCandidate.Parse(
            "alice@example.com",
            null);

        Assert.IsAssignableFrom<ICrossValidationCandidate>(candidate);
        Assert.False((object)candidate is IValidatedValue);
        Assert.Null(candidate.GetType().GetMethod("ExposeUnchecked"));
        Assert.Empty(typeof(CrossValidationCompletion<string, ExistingEmail>)
            .GetConstructors());
    }

    [Fact]
    public async Task ReceiverHasDistinctRuntimeAndMarkerType()
    {
        ExistingEmailCandidate candidate = ExistingEmailCandidate.Parse(
            "alice@example.com",
            null);
        ExistingEmail receiver = await candidate.ConfirmExistsAsync(
            new RecordingDirectory(exists: true));

        Assert.IsAssignableFrom<ICrossValidatedValue>(receiver);
        Assert.Equal(typeof(ExistingEmail), candidate.ReceiverType);
        Assert.NotEqual(candidate.GetType(), receiver.GetType());
        Assert.Equal("[sensitive]", receiver.ToString());
    }

    private interface IEmailDirectory
    {
        ValueTask<bool> ExistsAsync(string email, CancellationToken cancellationToken);
    }

    private sealed class RecordingDirectory(bool exists) : IEmailDirectory
    {
        public int CallCount { get; private set; }

        public ValueTask<bool> ExistsAsync(
            string email,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            CallCount++;
            return ValueTask.FromResult(exists);
        }
    }

    private sealed class ExistingEmailCandidate :
        CrossValidationCandidate<
            ExistingEmailCandidate,
            string,
            ExistingEmail,
            EmailTraits,
            BoundedStringArchetype<EmailTraits, RedactedPii<string>>,
            RedactedPii<string>>,
        ICrossValidationCandidateFactory<ExistingEmailCandidate, string>
    {
        private ExistingEmailCandidate(string locallyValidated)
            : base(locallyValidated)
        {
        }

        static ExistingEmailCandidate
            ICrossValidationCandidateFactory<ExistingEmailCandidate, string>.CreateValidated(
                string locallyValidatedValue) => new(locallyValidatedValue);

        public ValueTask<ExistingEmail> ConfirmExistsAsync(
            IEmailDirectory directory,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(directory);
            return CompleteCrossValidationAsync(
                async (value, token) =>
                    await directory.ExistsAsync(value, token).ConfigureAwait(false)
                        ? CrossValidationResult.Success
                        : CrossValidationResult.Failure(
                            "email.not_found",
                            "The email address is not registered."),
                cancellationToken);
        }
    }

    private sealed class ExistingEmail :
        ExposableCrossValidatedValue<ExistingEmail, string, RedactedPii<string>>,
        ICrossValidatedValueFactory<ExistingEmail, string>
    {
        private ExistingEmail(CrossValidationCompletion<string, ExistingEmail> completion)
            : base(completion)
        {
        }

        public static ExistingEmail CreateCrossValidated(
            CrossValidationCompletion<string, ExistingEmail> completion) => new(completion);
    }
}
