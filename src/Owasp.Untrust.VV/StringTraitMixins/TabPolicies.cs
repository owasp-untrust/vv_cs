#pragma warning disable CS1591

namespace Owasp.Untrust.VV.StringTraitMixins;

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
