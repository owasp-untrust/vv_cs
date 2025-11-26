namespace Owasp.Untrust.VV;

using System.Net;
using System.Net.Sockets;
using System.Diagnostics;

public interface IpAddressPolicy {
    static bool IsIPv4(IPAddress address) 
    {
        return (address.AddressFamily == AddressFamily.InterNetwork);
    }

    static bool IsIPv6(IPAddress address) 
    {
        return (address.AddressFamily == AddressFamily.InterNetworkV6);
    }

    static bool IsInternalIPv4(IPAddress address)
    {
        if (!IsIPv4(address))
        {
            return false;
        }

        var bytes = address.GetAddressBytes();
        Debug.Assert(bytes.Length == 4);

        byte b0 = bytes[0];
        byte b1 = bytes[1];

        // RFC1918 private ranges
        if (b0 == 10)
            return true;                      // 10.0.0.0/8

        if (b0 == 172 && b1 >= 16 && b1 <= 31)
            return true;                      // 172.16.0.0/12

        if (b0 == 192 && b1 == 168)
            return true;                      // 192.168.0.0/16

        // Treat loopback and link-local as internal as well
        if (b0 == 127)
            return true;                      // 127.0.0.0/8

        if (b0 == 169 && b1 == 254)
            return true;                      // 169.254.0.0/16 (link-local)

        return false;
    }

    static bool IsExternalIPv4(IPAddress address)
    {
        // Exclude internal
        if (IsInternalIPv4(address))
            return false;

        var bytes = address.GetAddressBytes();
        Debug.Assert(bytes.Length == 4);

        byte b0 = bytes[0];

        // Exclude obvious special ranges: 0.0.0.0/8, multicast, broadcast-ish
        if (b0 == 0)
        {
            return false;                     // 0.0.0.0/8
        }

        if (b0 >= 224 && b0 <= 239)
        {
            return false;                     // 224.0.0.0/4 multicast
        }

        if (address.Equals(IPAddress.Broadcast)) {
            return false;                     // 255.255.255.255
        }

        return true;
    }

    static bool IsInternalIPv6(IPAddress address)
    {
        if (!IsIPv6(address))
        {
            return false;
        }

        var bytes = address.GetAddressBytes();
        Debug.Assert(bytes.Length == 16);

        // Loopback or unspecified: treat as internal
        if (IPAddress.IPv6Loopback.Equals(address) || IPAddress.IPv6Any.Equals(address))
            return true;

        // Link-local: fe80::/10
        if (address.IsIPv6LinkLocal)
            return true;

        // Unique local: fc00::/7 (fc00–fdff)
        byte b0 = bytes[0];
        if ((b0 & 0xFE) == 0xFC)
            return true;

        return false;
    }

    static bool IsExternalIPv6(IPAddress address)
    {
        // Exclude internal
        if (IsInternalIPv6(address))
        {
            return false;
        }

        var bytes = address.GetAddressBytes();
        Debug.Assert(bytes.Length == 16);

        // Exclude multicast
        if (address.IsIPv6Multicast)
        {
            return false;
        }

        return true; // global unicast and other routable scopes
    }
    
    abstract static bool MatchesPolicy(IPAddress address);
}

public class AnyIp : IpAddressPolicy 
{
    public static bool MatchesPolicy(IPAddress address) => true;
}

public class InternalIp : IpAddressPolicy 
{
    public static bool MatchesPolicy(IPAddress address) => IpAddressPolicy.IsInternalIPv4(address) || IpAddressPolicy.IsInternalIPv6(address);
}

public class ExternalIp : IpAddressPolicy 
{
    public static bool MatchesPolicy(IPAddress address) => IpAddressPolicy.IsExternalIPv4(address) || IpAddressPolicy.IsExternalIPv6(address);
}

public class InternalIpV4 : IpAddressPolicy 
{
    public static bool MatchesPolicy(IPAddress address) => IpAddressPolicy.IsInternalIPv4(address);
}

public class ExternalIpV4 : IpAddressPolicy 
{
    public static bool MatchesPolicy(IPAddress address) => IpAddressPolicy.IsExternalIPv4(address);
}
