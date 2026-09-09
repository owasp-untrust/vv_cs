#pragma warning disable CS1591

using System.Net;
using Owasp.Untrust.VV.Core;
using Owasp.Untrust.ValueDescriptors.Disclosure;

namespace Owasp.Untrust.VV.Archetypes;

/// <summary>A parsed IP address constrained by an explicit address policy.</summary>
public abstract class IpAddressValue<TSelf, TDisclosure, TPolicy>
    : ExposableValidatedValue<TSelf, IPAddress, TDisclosure>
    where TSelf : IpAddressValue<TSelf, TDisclosure, TPolicy>, IIpAddressDefinition
    where TDisclosure : IDisclosurePolicy<IPAddress>
    where TPolicy : IIpAddressPolicy
{
    protected IpAddressValue(string raw, IFormatProvider? provider = null)
        : base(Validate(raw))
    {
    }

    public static string Format => "ip";

    private static IPAddress Validate(string? raw)
    {
        var nonNullRaw = ValidationPipeline.RequireRaw(raw);
        ValidationPipeline.Require(
            IPAddress.TryParse(nonNullRaw, out var parsed),
            "ip.parse",
            "The value is not a valid IP address.");
        ValidationPipeline.Require(
            TPolicy.IsAllowed(parsed!),
            "ip.policy",
            "The IP address is not allowed by this value type's policy.");
        ValidationPipeline.RequireNoIssue(TSelf.ValidateAdditional(parsed!));
        return parsed!;
    }
}
