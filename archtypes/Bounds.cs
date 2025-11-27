using System.Numerics;
using Microsoft.AspNetCore.Server.Kestrel.Core;

namespace Owasp.Untrust.VV.Archetypes;

public struct Bounds<TValue>
    where TValue : INumber<TValue>
{
    public record DummyRecord() { }
    public static readonly DummyRecord ALLOW_NEGATIVE_VALUES = new DummyRecord();

    public Bounds(TValue min, TValue max)
    {
        if (min < TValue.Zero || max < TValue.Zero) {
            throw new ArgumentOutOfRangeException(nameof(min), "Bounds must be non-negative.");
        }
        if (min > max) {
            throw new ArgumentException("min must be <= max.");       
        }
        Min = min;
        Max = max;
    }

    public Bounds(TValue min, TValue max, DummyRecord allowNegativeValues)
    {
        if (min > max) {
            throw new ArgumentException("min must be <= max.");       
        }
        Min = min;
        Max = max;
    }

    public readonly TValue Min;
    public readonly TValue Max;
}