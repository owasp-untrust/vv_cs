#pragma warning disable CS1591

using System.Diagnostics.CodeAnalysis;
using Xunit;
using System.Net;
using Owasp.Untrust.VV.Archetypes;
using Owasp.Untrust.VV.Core;
using Owasp.Untrust.ValueDescriptors.Disclosure;

namespace Owasp.Untrust.VV.Tests;

public sealed class CoreArchetypeTests
{
    [Fact]
    public void Single_line_accepts_unicode_scalar_but_rejects_controls_and_unpaired_surrogates()
    {
        Assert.Equal("Café 😀", SafeLine.Parse("Café 😀", null).ExposeUnchecked());
        Assert.False(SafeLine.TryParse("first\nsecond", null, out _));
        Assert.False(SafeLine.TryParse("bad\uD800", null, out _));
    }

    [Fact]
    public void Multiline_normalizes_line_endings_before_final_validation()
    {
        var value = SafeMultiline.Parse("first\r\nsecond\rthird", null);

        Assert.Equal("first\nsecond\nthird", value.ExposeUnchecked());
        Assert.False(SafeMultiline.TryParse("first\tsecond", null, out _));
    }

    [Fact]
    public void Hex_supports_checked_numeric_and_binary_conversion()
    {
        var value = HexIdentifier.Parse("abc", null);

        Assert.Equal(0xABC, value.ToInt32());
        Assert.Equal(new byte[] { 0x0A, 0xBC }, value.ToBytes());
        Assert.False(HexIdentifier.TryParse("0xAB", null, out _));
    }

    [Fact]
    public void Base64_variants_enforce_alphabet_and_padding()
    {
        Assert.Equal("hello", System.Text.Encoding.UTF8.GetString(StandardToken.Parse("aGVsbG8=", null).ToBytes()));
        Assert.False(StandardToken.TryParse("aGVsbG8", null, out _));
        Assert.False(StandardToken.TryParse("aG V=", null, out _));

        Assert.Equal(new byte[] { 0xFB, 0xFF }, UrlToken.Parse("-_8", null).ToBytes());
        Assert.False(UrlToken.TryParse("+/8=", null, out _));
        Assert.False(UrlToken.TryParse("A", null, out _));
    }

    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("10.0.0.1")]
    [InlineData("100.64.0.1")]
    [InlineData("192.0.2.1")]
    [InlineData("198.18.0.1")]
    [InlineData("203.0.113.1")]
    [InlineData("::1")]
    [InlineData("::ffff:127.0.0.1")]
    [InlineData("2001:db8::1")]
    [InlineData("2002:7f00:1::")]
    public void External_ip_rejects_non_public_and_special_use_ranges(string raw)
    {
        Assert.False(PublicIp.TryParse(raw, null, out _));
    }

    [Fact]
    public void External_ip_accepts_public_unicast()
    {
        Assert.Equal(IPAddress.Parse("8.8.8.8"), PublicIp.Parse("8.8.8.8", null).ExposeUnchecked());
    }

    private sealed class SafeLine
        : SingleLine<SafeLine, Public<string>, RejectTabs>,
          IBoundedStringDefinition,
          IParsable<SafeLine>
    {
        private SafeLine(string raw, IFormatProvider? provider) : base(raw, provider) { }
        public static Bounds<int> LengthBounds => new(1, 64);
        public static SafeLine Parse(string raw, IFormatProvider? provider) => new(raw, provider);
        public static bool TryParse(string? raw, IFormatProvider? provider, [MaybeNullWhen(false)] out SafeLine result) =>
            TryParseCore(raw, provider, static (value, format) => new SafeLine(value, format), out result);
    }

    private sealed class SafeMultiline
        : Multiline<SafeMultiline, Public<string>, RejectTabs>,
          IBoundedStringDefinition,
          IParsable<SafeMultiline>
    {
        private SafeMultiline(string raw, IFormatProvider? provider) : base(raw, provider) { }
        public static Bounds<int> LengthBounds => new(1, 64);
        public static SafeMultiline Parse(string raw, IFormatProvider? provider) => new(raw, provider);
        public static bool TryParse(string? raw, IFormatProvider? provider, [MaybeNullWhen(false)] out SafeMultiline result) =>
            TryParseCore(raw, provider, static (value, format) => new SafeMultiline(value, format), out result);
    }

    private sealed class HexIdentifier
        : HexString<HexIdentifier, Public<string>>,
          IBoundedStringDefinition,
          IParsable<HexIdentifier>
    {
        private HexIdentifier(string raw, IFormatProvider? provider) : base(raw, provider) { }
        public static Bounds<int> LengthBounds => new(1, 16);
        public static HexIdentifier Parse(string raw, IFormatProvider? provider) => new(raw, provider);
        public static bool TryParse(string? raw, IFormatProvider? provider, [MaybeNullWhen(false)] out HexIdentifier result) =>
            TryParseCore(raw, provider, static (value, format) => new HexIdentifier(value, format), out result);
    }

    private sealed class StandardToken
        : Base64<StandardToken, RedactedSecret<string>, StandardBase64>,
          IBoundedStringDefinition,
          IParsable<StandardToken>
    {
        private StandardToken(string raw, IFormatProvider? provider) : base(raw, provider) { }
        public static Bounds<int> LengthBounds => new(4, 64);
        public static StandardToken Parse(string raw, IFormatProvider? provider) => new(raw, provider);
        public static bool TryParse(string? raw, IFormatProvider? provider, [MaybeNullWhen(false)] out StandardToken result) =>
            TryParseCore(raw, provider, static (value, format) => new StandardToken(value, format), out result);
    }

    private sealed class UrlToken
        : Base64<UrlToken, RedactedSecret<string>, UrlSafeBase64>,
          IBoundedStringDefinition,
          IParsable<UrlToken>
    {
        private UrlToken(string raw, IFormatProvider? provider) : base(raw, provider) { }
        public static Bounds<int> LengthBounds => new(2, 64);
        public static UrlToken Parse(string raw, IFormatProvider? provider) => new(raw, provider);
        public static bool TryParse(string? raw, IFormatProvider? provider, [MaybeNullWhen(false)] out UrlToken result) =>
            TryParseCore(raw, provider, static (value, format) => new UrlToken(value, format), out result);
    }

    private sealed class PublicIp
        : IpAddressValue<PublicIp, Public<IPAddress>, ExternalIpAddress>,
          IIpAddressDefinition,
          IParsable<PublicIp>
    {
        private PublicIp(string raw, IFormatProvider? provider) : base(raw, provider) { }
        public static PublicIp Parse(string raw, IFormatProvider? provider) => new(raw, provider);
        public static bool TryParse(string? raw, IFormatProvider? provider, [MaybeNullWhen(false)] out PublicIp result) =>
            TryParseCore(raw, provider, static (value, format) => new PublicIp(value, format), out result);
    }
}
