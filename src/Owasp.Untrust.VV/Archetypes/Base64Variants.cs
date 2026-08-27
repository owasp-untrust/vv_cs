#pragma warning disable CS1591

namespace Owasp.Untrust.VV.Archetypes;

/// <summary>Canonical padded RFC 4648 Base64.</summary>
public readonly struct StandardBase64 : IBase64Variant
{
    public static string Format => "byte";

    public static bool IsValid(string value)
    {
        if (value.Length == 0 || (value.Length & 3) != 0)
        {
            return false;
        }

        var paddingStarted = false;
        var paddingCount = 0;
        foreach (var character in value)
        {
            if (character == '=')
            {
                paddingStarted = true;
                paddingCount++;
                if (paddingCount > 2)
                {
                    return false;
                }

                continue;
            }

            if (paddingStarted ||
                !((character >= 'A' && character <= 'Z') ||
                  (character >= 'a' && character <= 'z') ||
                  (character >= '0' && character <= '9') ||
                  character is '+' or '/'))
            {
                return false;
            }
        }

        Span<byte> destination = value.Length <= 1024
            ? stackalloc byte[value.Length]
            : new byte[value.Length];
        return Convert.TryFromBase64String(value, destination, out _);
    }

    public static byte[] Decode(string value) => Convert.FromBase64String(value);
}

/// <summary>
/// RFC 4648 URL-safe Base64. Canonical padded and unpadded inputs are accepted;
/// standard '+' and '/' alphabet characters are rejected.
/// </summary>
public readonly struct UrlSafeBase64 : IBase64Variant
{
    public static string Format => "base64url";

    public static bool IsValid(string value)
    {
        if (value.Length == 0 || value.Length % 4 == 1)
        {
            return false;
        }

        var paddingStarted = false;
        var paddingCount = 0;
        foreach (var character in value)
        {
            if (character == '=')
            {
                paddingStarted = true;
                paddingCount++;
                if (paddingCount > 2)
                {
                    return false;
                }

                continue;
            }

            if (paddingStarted ||
                !((character >= 'A' && character <= 'Z') ||
                  (character >= 'a' && character <= 'z') ||
                  (character >= '0' && character <= '9') ||
                  character is '-' or '_'))
            {
                return false;
            }
        }

        if (paddingCount > 0 && (value.Length & 3) != 0)
        {
            return false;
        }

        try
        {
            _ = Decode(value);
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    public static byte[] Decode(string value)
    {
        var standard = value.Replace('-', '+').Replace('_', '/');
        var missingPadding = (4 - (standard.Length & 3)) & 3;
        if (missingPadding != 0)
        {
            standard = standard.PadRight(standard.Length + missingPadding, '=');
        }

        return Convert.FromBase64String(standard);
    }
}
