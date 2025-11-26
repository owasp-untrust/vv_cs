using System;
using System.Text.RegularExpressions;
using Owasp.Untrust.VV.Archetypes;

namespace Owasp.Untrust.VV.Core;

public abstract class HexStringBase<TWrapper> : RegexStringBase<TWrapper>
where TWrapper : HexStringBase<TWrapper>, ICreatable<TWrapper, string>
{
    protected HexStringBase() {
        RegexOptions = RegexOptions.CultureInvariant | RegexOptions.IgnoreCase;
    }
    
    /// <summary>
    /// Interpret the hex value as a non-negative 32-bit integer.
    /// Throws OverflowException if too large.
    /// </summary>
    public int ToInt32()
    {
        return Convert.ToInt32(Value, 16);
    }

    /// <summary>
    /// Interpret the hex value as a non-negative 64-bit integer.
    /// Throws OverflowException if too large.
    /// </summary>
    public long ToInt64()
    {
        return Convert.ToInt64(Value, 16);
    }

    /// <summary>
    /// Convert the hex value into a big-endian byte array.
    /// If the number of hex digits is odd, a leading '0' nibble is assumed.
    /// </summary>
    public byte[] ToBytes()
    {
        var s = Value;
        if (string.IsNullOrEmpty(s))
        {
            return Array.Empty<byte>();
        }

        // If odd number of hex digits, left-pad with a zero nibble.
        if ((s.Length & 1) != 0)
        {
            s = "0" + s;
        }

        int byteCount = s.Length / 2;
        var bytes = new byte[byteCount];
        for (int i = 0; i < byteCount; i++)
        {
            string hexByte = s.Substring(i * 2, 2);
            bytes[i] = Convert.ToByte(hexByte, 16);
        }

        return bytes;
    }

    /// <summary>
    /// Canonical hex pattern (no 0x prefix, upper/lower mixed allowed).
    /// </summary>
    protected sealed override string PatternConstraint() { return "^[0-9A-Fa-f]+$"; }
    protected sealed override Type? SharedRegexKey() { return typeof(HexString<>); }
}
