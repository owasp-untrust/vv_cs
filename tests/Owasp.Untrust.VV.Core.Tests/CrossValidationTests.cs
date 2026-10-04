#pragma warning disable CS1591
using Xunit;
using Owasp.Untrust.VV.Core;
using Owasp.Untrust.VV.CrossValidation;
using Owasp.Untrust.VV.Traits;
using Owasp.Untrust.ValueDescriptors.Disclosure;

namespace Owasp.Untrust.VV.Core.Tests;

public sealed class CrossValidationTests
{
    [Fact]
    public async Task ParsingPerformsOnlyLocalValidation()
    {
        ExistingPortCandidate candidate = ExistingPortCandidate.Parse(
            "443",
            null);
        RecordingDirectory directory = new(exists: true);

        Assert.Equal(0, directory.CallCount);

        ExistingPort receiver = await candidate.ConfirmExistsAsync(directory);

        Assert.Equal(1, directory.CallCount);
        Assert.Equal(443, receiver.ExposeUnchecked());
    }

    [Fact]
    public async Task FailedCrossValidationCannotProduceReceiverAndDoesNotLeakInput()
    {
        const string input = "404";
        ExistingPortCandidate candidate = ExistingPortCandidate.Parse(input, null);

        CrossValidationException failure = await Assert.ThrowsAsync<CrossValidationException>(
            async () => await candidate.ConfirmExistsAsync(new RecordingDirectory(exists: false)));

        Assert.Equal("port.not_found", failure.ErrorCode);
        Assert.DoesNotContain(input, failure.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task CancellationCannotMintCompletion()
    {
        ExistingPortCandidate candidate = ExistingPortCandidate.Parse(
            "443",
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
        ExistingPortCandidate candidate = ExistingPortCandidate.Parse(
            "443",
            null);

        Assert.IsAssignableFrom<ICrossValidationCandidate>(candidate);
        Assert.False((object)candidate is IValidatedValue);
        Assert.Null(candidate.GetType().GetMethod("ExposeUnchecked"));
        Assert.Empty(typeof(CrossValidationCompletion<int, ExistingPort>)
            .GetConstructors());
    }

    [Fact]
    public async Task ReceiverHasDistinctRuntimeAndMarkerType()
    {
        ExistingPortCandidate candidate = ExistingPortCandidate.Parse(
            "443",
            null);
        ExistingPort receiver = await candidate.ConfirmExistsAsync(
            new RecordingDirectory(exists: true));

        Assert.IsAssignableFrom<ICrossValidatedValue>(receiver);
        Assert.Equal(typeof(ExistingPort), candidate.ReceiverType);
        Assert.NotEqual(candidate.GetType(), receiver.GetType());
        Assert.Equal("[sensitive]", receiver.ToString());
    }

    private interface IPortDirectory
    {
        ValueTask<bool> ExistsAsync(int port, CancellationToken cancellationToken);
    }

    private sealed class RecordingDirectory(bool exists) : IPortDirectory
    {
        public int CallCount { get; private set; }

        public ValueTask<bool> ExistsAsync(
            int port,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            CallCount++;
            return ValueTask.FromResult(exists);
        }
    }

    private sealed class ExistingPortCandidate :
        CrossValidationCandidate<
            ExistingPortCandidate,
            int,
            ExistingPort,
            PortTraits,
            RedactedPii<int>>,
        ICrossValidationCandidateFactory<ExistingPortCandidate, int>
    {
        private ExistingPortCandidate(int locallyValidated)
            : base(locallyValidated)
        {
        }

        static ExistingPortCandidate
            ICrossValidationCandidateFactory<ExistingPortCandidate, int>.CreateValidated(
                PostValidationRawValue<int, ExistingPortCandidate> validated) =>
            new(validated.ValueForReadyConstruction);

        public ValueTask<ExistingPort> ConfirmExistsAsync(
            IPortDirectory directory,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(directory);
            return CompleteCrossValidationAsync(
                async (value, token) =>
                    await directory.ExistsAsync(value, token).ConfigureAwait(false)
                        ? CrossValidationResult.Success
                        : CrossValidationResult.Failure(
                            "port.not_found",
                            "The port is not registered."),
                cancellationToken);
        }
    }

    private sealed class ExistingPort :
        ExposableCrossValidatedValue<ExistingPort, int, RedactedPii<int>>,
        ICrossValidatedValueFactory<ExistingPort, int>
    {
        private ExistingPort(CrossValidationCompletion<int, ExistingPort> completion)
            : base(completion)
        {
        }

        public static ExistingPort CreateCrossValidated(
            CrossValidationCompletion<int, ExistingPort> completion) => new(completion);
    }

    private readonly struct PortTraits : IParsableTraits<int>
    {
        public static int NormalizeValue(int value) => value;

        public static ValidationIssue? ValidateValue(int value) =>
            value is > 0 and <= 65_535
                ? null
                : new ValidationIssue("port.range", "The port is outside the supported range.");
    }
}
