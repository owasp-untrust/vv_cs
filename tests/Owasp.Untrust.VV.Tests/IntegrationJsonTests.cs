using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using System.Text.Json;
using Microsoft.AspNetCore.Http.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Owasp.Untrust.VV.Archetypes;
using Owasp.Untrust.VV.AspNetCore;
using Owasp.Untrust.VV.Core;
using Owasp.Untrust.VV.CrossValidation;
using Owasp.Untrust.VV.EntityAccess;
using Owasp.Untrust.ValueDescriptors.Disclosure;
using Xunit;

namespace Owasp.Untrust.VV.Tests;

/// <summary>Exercises the ASP.NET JSON integration's security boundaries.</summary>
public sealed class IntegrationJsonTests
{
    /// <summary>JSON input delegates to the validated type's IParsable implementation.</summary>
    [Fact]
    public void AddValidatedValues_UsesTheIParsableValidationPath()
    {
        var options = CreateJsonOptions();

        var parsed = JsonSerializer.Deserialize<IntegrationPublicText>("\"valid\"", options);

        Assert.NotNull(parsed);
        Assert.Equal("valid", parsed!.ExposeUnchecked());

        var exception = Assert.Throws<JsonException>(() =>
            JsonSerializer.Deserialize<IntegrationPublicText>(
                "\"this rejected value is far too long\"",
                options));
        Assert.DoesNotContain("this rejected value", exception.Message);
    }

    /// <summary>Sensitive output uses the classified public representation.</summary>
    [Fact]
    public void Serialization_UsesTheSafeDisclosureRepresentation()
    {
        var options = CreateJsonOptions();
        var secret = IntegrationSecretText.Parse("private", provider: null);

        var json = JsonSerializer.Serialize(secret, options);

        Assert.Equal("\"[sensitive]\"", json);
        Assert.DoesNotContain("private", json);
    }

    /// <summary>Optional values preserve Some/None semantics in JSON.</summary>
    [Fact]
    public void Optional_MapsNullToNoneAndScalarsToSome()
    {
        var options = CreateJsonOptions();

        var none = JsonSerializer.Deserialize<Optional<IntegrationPublicText>>("null", options);
        var some = JsonSerializer.Deserialize<Optional<IntegrationPublicText>>("\"valid\"", options);

        Assert.False(none.HasValue);
        Assert.True(some.HasValue);
        Assert.Equal("valid", some.NonNull.ExposeUnchecked());
        Assert.Equal("null", JsonSerializer.Serialize(Optional<IntegrationPublicText>.None, options));
        Assert.Equal("\"valid\"", JsonSerializer.Serialize(some, options));
    }

    /// <summary>Incomplete candidates cannot leave the service and receivers cannot enter it.</summary>
    [Fact]
    public void CandidateOutputAndReceiverInputFailClosed()
    {
        var options = CreateJsonOptions();
        var candidate = IntegrationCandidate.Parse("locally-valid", provider: null);

        Assert.Throws<JsonException>(() => JsonSerializer.Serialize(candidate, options));
        Assert.Throws<JsonException>(() =>
            JsonSerializer.Deserialize<IntegrationReceiver>("\"trusted\"", options));
    }

    [Fact]
    public void EntityCandidateAndAuthorizationEvidenceFailClosedAtJsonBoundary()
    {
        var options = CreateJsonOptions();
        var candidate = IntegrationEntityCandidate.Parse("document-1", provider: null);
        var evidence = (AuthorizedEntity<string, IntegrationRead>)Activator.CreateInstance(
            typeof(AuthorizedEntity<string, IntegrationRead>),
            BindingFlags.Instance | BindingFlags.NonPublic,
            binder: null,
            args: ["stored entity"],
            culture: null)!;

        Assert.Throws<JsonException>(() => JsonSerializer.Serialize(candidate, options));
        Assert.Throws<JsonException>(() => JsonSerializer.Serialize(evidence, options));
        Assert.Throws<JsonException>(() =>
            JsonSerializer.Deserialize<AuthorizedEntity<string, IntegrationRead>>("{}", options));
    }

    private static JsonSerializerOptions CreateJsonOptions()
    {
        var services = new ServiceCollection();
        services.AddValidatedValues();
        using var provider = services.BuildServiceProvider();
        return new JsonSerializerOptions(
            provider.GetRequiredService<IOptions<JsonOptions>>().Value.SerializerOptions);
    }

    private sealed class IntegrationPublicText :
        BoundedString<IntegrationPublicText, Public<string>>,
        IBoundedStringDefinition,
        IParsable<IntegrationPublicText>
    {
        private IntegrationPublicText(string raw, IFormatProvider? provider)
            : base(raw, provider)
        {
        }

        public static Bounds<int> LengthBounds => new(1, 16);

        public static IntegrationPublicText Parse(string raw, IFormatProvider? provider) =>
            new(raw, provider);

        public static bool TryParse(
            string? raw,
            IFormatProvider? provider,
            [MaybeNullWhen(false)] out IntegrationPublicText result)
        {
            var succeeded = TryParseCore(
                raw,
                provider,
                static (value, formatProvider) => new IntegrationPublicText(value, formatProvider),
                out var parsed);
            result = parsed!;
            return succeeded;
        }
    }

    private sealed class IntegrationSecretText :
        BoundedString<IntegrationSecretText, RedactedSecret<string>>,
        IBoundedStringDefinition,
        IParsable<IntegrationSecretText>
    {
        private IntegrationSecretText(string raw, IFormatProvider? provider)
            : base(raw, provider)
        {
        }

        public static Bounds<int> LengthBounds => new(1, 16);

        public static IntegrationSecretText Parse(string raw, IFormatProvider? provider) =>
            new(raw, provider);

        public static bool TryParse(
            string? raw,
            IFormatProvider? provider,
            [MaybeNullWhen(false)] out IntegrationSecretText result)
        {
            var succeeded = TryParseCore(
                raw,
                provider,
                static (value, formatProvider) => new IntegrationSecretText(value, formatProvider),
                out var parsed);
            result = parsed!;
            return succeeded;
        }
    }

    private sealed class IntegrationCandidate :
        ICrossValidationCandidate,
        IParsable<IntegrationCandidate>
    {
        private readonly string _value;

        private IntegrationCandidate(string value)
        {
            _value = value;
        }

        public Type ReceiverType => typeof(IntegrationReceiver);

        public object ToPublicValue() => _value;

        public string ToPublicString() => _value;

        public static IntegrationCandidate Parse(string raw, IFormatProvider? provider)
        {
            if (string.IsNullOrWhiteSpace(raw))
                throw new ArgumentException("Value cannot be null or whitespace.", nameof(raw));

            return new IntegrationCandidate(raw);
        }

        public static bool TryParse(
            string? raw,
            IFormatProvider? provider,
            [MaybeNullWhen(false)] out IntegrationCandidate result)
        {
            if (!string.IsNullOrWhiteSpace(raw))
            {
                result = new IntegrationCandidate(raw);
                return true;
            }

            result = null!;
            return false;
        }
    }

    private sealed class IntegrationReceiver : ICrossValidatedValue
    {
        public Type ValueType => typeof(string);

        public object ToPublicValue() => "trusted";

        public string ToPublicString() => "trusted";
    }

    private sealed class IntegrationRead : IEntityOperation;

    private sealed class IntegrationEntityCandidate :
        IEntityResolutionCandidate,
        IParsable<IntegrationEntityCandidate>
    {
        private readonly string _id;

        private IntegrationEntityCandidate(string id)
        {
            _id = id;
        }

        public Type EntityIdType => typeof(string);

        public object ToPublicValue() => _id;

        public string ToPublicString() => _id;

        public static IntegrationEntityCandidate Parse(string raw, IFormatProvider? provider)
        {
            if (string.IsNullOrWhiteSpace(raw))
                throw new ArgumentException("Value cannot be null or whitespace.", nameof(raw));

            return new IntegrationEntityCandidate(raw);
        }

        public static bool TryParse(
            string? raw,
            IFormatProvider? provider,
            [MaybeNullWhen(false)] out IntegrationEntityCandidate result)
        {
            if (!string.IsNullOrWhiteSpace(raw))
            {
                result = new IntegrationEntityCandidate(raw);
                return true;
            }

            result = null!;
            return false;
        }
    }
}
