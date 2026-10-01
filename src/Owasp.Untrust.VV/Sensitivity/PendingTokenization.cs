#pragma warning disable CS1591
using Owasp.Untrust.VV.Core;
using Owasp.Untrust.ValueDescriptors.Core;
using Owasp.Untrust.ValueDescriptors.Disclosure;

namespace Owasp.Untrust.VV.Sensitivity;

public sealed class PendingTokenization<TValue> : PendingSensitiveValue<TValue>
    where TValue : notnull
{
    public PendingTokenization(IValidatedValue<TValue> source)
        : base(source)
    {
    }

    public async ValueTask<TokenOnlyValue<TValue, TDisclosure>> TokenizeOnlyAsync<TDisclosure>(
        ITokenizationProvider<TValue> provider,
        CancellationToken cancellationToken = default)
        where TDisclosure : IDisclosurePolicy<string>
    {
        string token = await TokenizeAsync(provider, cancellationToken).ConfigureAwait(false);
        return new TokenOnlyValue<TValue, TDisclosure>(token);
    }

    public async ValueTask<RetainedTokenizedValue<TValue, TDisclosure>> TokenizeRetainingPlaintextAsync<TDisclosure>(
        ITokenizationProvider<TValue> provider,
        CancellationToken cancellationToken = default)
        where TDisclosure : IDisclosurePolicy<string>
    {
        string token = await TokenizeAsync(provider, cancellationToken).ConfigureAwait(false);
        return new RetainedTokenizedValue<TValue, TDisclosure>(
            RawValueForExplicitRetention,
            token);
    }

    private async ValueTask<string> TokenizeAsync(
        ITokenizationProvider<TValue> provider,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(provider);
        cancellationToken.ThrowIfCancellationRequested();

        string token = await provider
            .TokenizeAsync(ExposeForTransformation(), cancellationToken)
            .ConfigureAwait(false);

        cancellationToken.ThrowIfCancellationRequested();
        if (string.IsNullOrWhiteSpace(token))
        {
            throw new InvalidOperationException("The tokenization provider returned no token.");
        }

        return token;
    }
}
