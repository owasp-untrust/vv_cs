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

public sealed class TokenOnlyValue<TValue, TDisclosure> :
    IPubliclyRepresentable,
    ITransformedOnlyValue
    where TValue : notnull
    where TDisclosure : IDisclosurePolicy<string>
{
    internal TokenOnlyValue(string token)
    {
        Token = token ?? throw new ArgumentNullException(nameof(token));
    }

    public string Token { get; }

    public object? ToPublicValue() =>
        PublicRepresentation<string, TDisclosure>.ToPublicValue(Token);

    public string ToPublicString() =>
        PublicRepresentation<string, TDisclosure>.ToPublicString(Token);

    public override string ToString() => ToPublicString();
}

public sealed class RetainedTokenizedValue<TValue, TDisclosure> :
    IPubliclyRepresentable,
    IExposableValue<TValue>,
    IRetainsPlaintextValue
    where TValue : notnull
    where TDisclosure : IDisclosurePolicy<string>
{
    private readonly TValue _plaintext;

    internal RetainedTokenizedValue(
        TValue plaintext,
        string token)
    {
        _plaintext = plaintext ?? throw new ArgumentNullException(nameof(plaintext));
        Token = token ?? throw new ArgumentNullException(nameof(token));
    }

    public string Token { get; }

    public TValue ExposeUnchecked() => _plaintext;

    public object? ToPublicValue() =>
        PublicRepresentation<string, TDisclosure>.ToPublicValue(Token);

    public string ToPublicString() =>
        PublicRepresentation<string, TDisclosure>.ToPublicString(Token);

    public override string ToString() => ToPublicString();
}

public static class TokenizationLifecycleExtensions
{
    public static PendingTokenization<TValue> PendingTokenization<TValue>(
        this IValidatedValue<TValue> source)
        where TValue : notnull => new(source);
}
