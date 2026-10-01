#pragma warning disable CS1591

using System.Numerics;

namespace Owasp.Untrust.VV.Core;

/// <summary>Static contract required by bounded numeric leaves.</summary>
public interface IBoundedNumber<TValue>
    where TValue : notnull, INumber<TValue>
{
    static abstract Bounds<TValue> Bounds { get; }
}
