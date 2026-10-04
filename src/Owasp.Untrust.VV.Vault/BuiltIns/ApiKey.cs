using System.Text.RegularExpressions;
using Owasp.Untrust.VV.Archetypes;
using Owasp.Untrust.VV.Core;
using Owasp.Untrust.VV.StringTraitMixins;
using Owasp.Untrust.VV.Traits;
using Owasp.Untrust.ValueDescriptors.Disclosure;
using Owasp.Untrust.ValueDescriptors;
using static Owasp.Untrust.ValueDescriptors.RegexAsciiFactory;

namespace Owasp.Untrust.VV.Vault;

/// <summary>A locally validated API key that must be stored in a vault before it can be used.</summary>
public sealed class PendingApiKey
    : PendingVaultString<
        PendingApiKey,
        VaultStoredApiKey,
        ApiKeyTraits
    >
    , IValidatedValueWrapperFactory<PendingApiKey, string>
{
    private PendingApiKey(string validatedValue)
        : base(validatedValue)
    {
    }

    static PendingApiKey IValidatedValueWrapperFactory<PendingApiKey, string>.CreateValidated(
        PostValidationRawValue<string, PendingApiKey> validated) => new(validated.ValueForReadyConstruction);
}

/// <summary>An API key held in a vault and retrieved only through an explicit asynchronous boundary.</summary>
public sealed class VaultStoredApiKey
    : VaultStoredValue<VaultStoredApiKey, string>
    , IInternallyTransformedValueFactory<VaultStoredApiKey, VaultStorageReceipt<string>>
{
    private VaultStoredApiKey(InternallyTransformedValue<VaultStoredApiKey, VaultStorageReceipt<string>> stored)
        : base(stored)
    {
    }

    static VaultStoredApiKey IInternallyTransformedValueFactory<VaultStoredApiKey, VaultStorageReceipt<string>>.CreateTransformed(
        InternallyTransformedValue<VaultStoredApiKey, VaultStorageReceipt<string>> stored) => new(stored);

    protected override string RevalidateRetrievedValue(string value) =>
        LocalValidation.ParseAndValidate<string, ApiKeyTraits, RegexStringArchetype<ApiKeyTraits, MaskedApiKey>, MaskedApiKey>(value);
}

/// <summary>Stable public API-key representation: only the final four characters are visible.</summary>
public readonly struct MaskedApiKey : IDisclosurePolicy<string>
{
    private const int DISPLAY_SUFFIX_LENGTH = 4;

    public static string ToPublicString(string value) => "****" + value[^DISPLAY_SUFFIX_LENGTH..];
}

/// <summary>Local syntax, length, and disclosure rules shared by pending and vault-stored API keys.</summary>
public class ApiKeyTraits 
    : StringTraits<
        ApiKeyTraits,
        AsciiRegexValidator<ApiKeyTraits>>,
      ILengthBoundsTraits<ApiKeyTraits>,
      IAsciiRegexPattern<ApiKeyTraits>
{
    public static Bounds<int> LengthBounds => new(20, 512);

    public static RegexAscii Pattern => RegexAscii("\\A[A-Za-z0-9_-]{20,512}\\z");

    public static TimeSpan MatchTimeout => TimeSpan.FromMilliseconds(100);
}
