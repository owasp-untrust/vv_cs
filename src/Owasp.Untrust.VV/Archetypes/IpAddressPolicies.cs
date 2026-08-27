#pragma warning disable CS1591

using System.Net;
using System.Net.Sockets;

namespace Owasp.Untrust.VV.Archetypes;

/// <summary>Accepts any syntactically valid IP address.</summary>
public readonly struct AnyIpAddress : IIpAddressPolicy
{
    public static bool IsAllowed(IPAddress address) => true;
}

/// <summary>Accepts loopback, link-local, and private-use addresses.</summary>
public readonly struct InternalIpAddress : IIpAddressPolicy
{
    public static bool IsAllowed(IPAddress address) => IpAddressRanges.IsInternal(address);
}

/// <summary>Accepts globally routable unicast addresses and rejects special-use ranges.</summary>
public readonly struct ExternalIpAddress : IIpAddressPolicy
{
    public static bool IsAllowed(IPAddress address) => IpAddressRanges.IsExternal(address);
}

internal static class IpAddressRanges
{
    internal static bool IsInternal(IPAddress address)
    {
        var normalized = NormalizeMapped(address);
        if (IPAddress.IsLoopback(normalized))
        {
            return true;
        }

        if (normalized.AddressFamily == AddressFamily.InterNetwork)
        {
            return InIpv4Cidr(normalized, 0x0A000000, 8) ||
                   InIpv4Cidr(normalized, 0xAC100000, 12) ||
                   InIpv4Cidr(normalized, 0xC0A80000, 16) ||
                   InIpv4Cidr(normalized, 0xA9FE0000, 16);
        }

        if (normalized.AddressFamily != AddressFamily.InterNetworkV6)
        {
            return false;
        }

        var bytes = normalized.GetAddressBytes();
        return normalized.IsIPv6LinkLocal || (bytes[0] & 0xFE) == 0xFC;
    }

    internal static bool IsExternal(IPAddress address)
    {
        var normalized = NormalizeMapped(address);
        if (normalized.AddressFamily == AddressFamily.InterNetwork)
        {
            return !InIpv4Cidr(normalized, 0x00000000, 8) &&
                   !InIpv4Cidr(normalized, 0x0A000000, 8) &&
                   !InIpv4Cidr(normalized, 0x64400000, 10) &&
                   !InIpv4Cidr(normalized, 0x7F000000, 8) &&
                   !InIpv4Cidr(normalized, 0xA9FE0000, 16) &&
                   !InIpv4Cidr(normalized, 0xAC100000, 12) &&
                   !InIpv4Cidr(normalized, 0xC0000000, 24) &&
                   !InIpv4Cidr(normalized, 0xC0000200, 24) &&
                   !InIpv4Cidr(normalized, 0xC0586300, 24) &&
                   !InIpv4Cidr(normalized, 0xC0A80000, 16) &&
                   !InIpv4Cidr(normalized, 0xC6120000, 15) &&
                   !InIpv4Cidr(normalized, 0xC6336400, 24) &&
                   !InIpv4Cidr(normalized, 0xCB007100, 24) &&
                   !InIpv4Cidr(normalized, 0xE0000000, 4) &&
                   !InIpv4Cidr(normalized, 0xF0000000, 4);
        }

        if (normalized.AddressFamily != AddressFamily.InterNetworkV6 ||
            normalized.Equals(IPAddress.IPv6Any) ||
            normalized.Equals(IPAddress.IPv6Loopback) ||
            normalized.IsIPv6LinkLocal ||
            normalized.IsIPv6Multicast)
        {
            return false;
        }

        var bytes = normalized.GetAddressBytes();
        if ((bytes[0] & 0xFE) == 0xFC)
        {
            return false;
        }

        return !InIpv6Cidr(bytes, new byte[] { 0x00, 0x00 }, 96) &&
               !InIpv6Cidr(bytes, new byte[] { 0x00, 0x64, 0xFF, 0x9B }, 32) &&
               !InIpv6Cidr(bytes, new byte[] { 0x01, 0x00 }, 64) &&
               !InIpv6Cidr(bytes, new byte[] { 0x20, 0x01, 0x00, 0x02 }, 48) &&
               !InIpv6Cidr(bytes, new byte[] { 0x20, 0x01, 0x00, 0x10 }, 28) &&
               !InIpv6Cidr(bytes, new byte[] { 0x20, 0x01, 0x0D, 0xB8 }, 32) &&
               !InIpv6Cidr(bytes, new byte[] { 0x20, 0x02 }, 16);
    }

    private static IPAddress NormalizeMapped(IPAddress address) =>
        address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;

    private static bool InIpv4Cidr(IPAddress address, uint network, int prefixLength)
    {
        var bytes = address.GetAddressBytes();
        var candidate = ((uint)bytes[0] << 24) |
                        ((uint)bytes[1] << 16) |
                        ((uint)bytes[2] << 8) |
                        bytes[3];
        var mask = prefixLength == 0 ? 0U : uint.MaxValue << (32 - prefixLength);
        return (candidate & mask) == (network & mask);
    }

    private static bool InIpv6Cidr(byte[] candidate, byte[] prefix, int prefixLength)
    {
        var wholeBytes = prefixLength / 8;
        var remainingBits = prefixLength % 8;

        for (var index = 0; index < wholeBytes; index++)
        {
            var expected = index < prefix.Length ? prefix[index] : (byte)0;
            if (candidate[index] != expected)
            {
                return false;
            }
        }

        if (remainingBits == 0)
        {
            return true;
        }

        var mask = (byte)(0xFF << (8 - remainingBits));
        var partialExpected = wholeBytes < prefix.Length ? prefix[wholeBytes] : (byte)0;
        return (candidate[wholeBytes] & mask) == (partialExpected & mask);
    }
}
