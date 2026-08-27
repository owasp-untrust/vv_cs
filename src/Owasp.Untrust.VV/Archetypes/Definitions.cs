#pragma warning disable CS1591

using System.Numerics;
using System.Net;
using System.Text.RegularExpressions;
using Owasp.Untrust.VV.Core;

namespace Owasp.Untrust.VV.Archetypes;

/// <summary>Static definition required by bounded string leaves.</summary>
public interface IBoundedStringDefinition
{
    static abstract Bounds<int> LengthBounds { get; }

    static virtual string Normalize(string raw) => raw;

    static virtual ValidationIssue? ValidateAdditional(string normalized) => null;

}

/// <summary>Static definition required by regex string leaves.</summary>
public interface IRegexStringDefinition : IBoundedStringDefinition
{
    static abstract string Pattern { get; }

    static virtual RegexOptions Options => RegexOptions.CultureInvariant;

    static virtual TimeSpan MatchTimeout => TimeSpan.FromMilliseconds(100);
}

/// <summary>Static definition required by bounded numeric leaves.</summary>
public interface IBoundedNumberDefinition<TValue>
    where TValue : notnull, INumber<TValue>
{
    static abstract Bounds<TValue> Bounds { get; }

    static virtual TValue Normalize(TValue parsed) => parsed;

    static virtual ValidationIssue? ValidateAdditional(TValue normalized) => null;

}

/// <summary>Controls whether an otherwise safe single/multiline value accepts tabs.</summary>
public interface ITabPolicy
{
    static abstract bool AllowsTab { get; }
}

/// <summary>Rejects tabs.</summary>
public readonly struct RejectTabs : ITabPolicy
{
    public static bool AllowsTab => false;
}

/// <summary>Accepts tabs.</summary>
public readonly struct AcceptTabs : ITabPolicy
{
    public static bool AllowsTab => true;
}

/// <summary>Defines a Base64 alphabet and padding policy.</summary>
public interface IBase64Variant
{
    static abstract bool IsValid(string value);

    static abstract byte[] Decode(string value);

    static abstract string Format { get; }
}

/// <summary>Static definition required by IP-address leaves.</summary>
public interface IIpAddressDefinition
{
    static virtual ValidationIssue? ValidateAdditional(IPAddress address) => null;
}

/// <summary>Controls which parsed IP addresses a named leaf accepts.</summary>
public interface IIpAddressPolicy
{
    static abstract bool IsAllowed(IPAddress address);
}
