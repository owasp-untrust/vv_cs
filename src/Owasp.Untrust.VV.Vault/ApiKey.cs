using System.Text.RegularExpressions;
using Owasp.Untrust.VV.Archetypes;
using Owasp.Untrust.VV.Core;
using Owasp.Untrust.ValueDescriptors.Disclosure;

namespace Owasp.Untrust.VV.Vault;

/// <summary>A locally validated API key that must be stored in a vault before it can be used.</summary>
public sealed class PendingApiKey :
    PendingVaultValue<
        PendingApiKey,
        string,
        VaultStoredApiKey,
        ApiKeyTraits,
        RegexStringArchetype<ApiKeyTraits, MaskedApiKey>,
        MaskedApiKey>,
    IInternallyValidatedValueFactory<PendingApiKey, string>
{
    private PendingApiKey(string validatedValue)
        : base(validatedValue)
    {
    }

    static PendingApiKey IInternallyValidatedValueFactory<PendingApiKey, string>.CreateValidated(
        InternallyValidatedValue<string, PendingApiKey> validated) => new(validated.ValueForReadyConstruction);
}

/// <summary>An API key held in a vault and retrieved only through an explicit asynchronous boundary.</summary>
public sealed class VaultStoredApiKey :
    VaultStoredValue<VaultStoredApiKey, string>,
    IInternallyTransformedValueFactory<VaultStoredApiKey, VaultStorageReceipt<string>>
{
    private VaultStoredApiKey(InternallyTransformedValue<VaultStorageReceipt<string>, VaultStoredApiKey> stored)
        : base(stored)
    {
    }

    static VaultStoredApiKey IInternallyTransformedValueFactory<VaultStoredApiKey, VaultStorageReceipt<string>>.CreateTransformed(
        InternallyTransformedValue<VaultStorageReceipt<string>, VaultStoredApiKey> stored) => new(stored);

    protected override string RevalidateRetrievedValue(string value) =>
        LocalValidation.ParseAndValidate<string, ApiKeyTraits, RegexStringArchetype<ApiKeyTraits, MaskedApiKey>, MaskedApiKey>(value);
}

/// <summary>Stable public API-key representation: only the final four characters are visible.</summary>
public readonly struct MaskedApiKey : IDisclosurePolicy<string>
{
    private const int DISPLAY_SUFFIX_LENGTH = 4;

    public static object ToPublicValue(string value) => ToPublicString(value);

    public static string ToPublicString(string value) => "****" + value[^DISPLAY_SUFFIX_LENGTH..];
}

/// <summary>Local syntax, length, and disclosure rules shared by pending and vault-stored API keys.</summary>
public readonly struct ApiKeyTraits : IRegexStringTraits<ApiKeyTraits, MaskedApiKey>
{
    public static Bounds<int> LengthBounds => new(20, 512);

    public static string Pattern => "\\A[A-Za-z0-9_-]{20,512}\\z";

    public static RegexOptions Options => RegexOptions.CultureInvariant;

    public static TimeSpan MatchTimeout => TimeSpan.FromMilliseconds(100);

    public static bool TryParse(string raw, IFormatProvider? provider, out string value)
    {
        value = raw;
        return true;
    }

    public static string Normalize(string value) => value;

    public static ValidationIssue? ValidateAdditional(string normalized) => null;
}
