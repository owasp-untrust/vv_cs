using System.Numerics;
using Microsoft.AspNetCore.Server.Kestrel.Core;

public struct Bounds<ValueT>
    where ValueT : INumber<ValueT>
{
    public record DummyRecord() { }
    public static readonly DummyRecord ALLOW_NEGATIVE_VALUES = new DummyRecord();

    public Bounds(ValueT min, ValueT max)
    {
        if (min < ValueT.Zero || max < ValueT.Zero) {
            throw new ArgumentOutOfRangeException(nameof(min), "Bounds must be non-negative.");
        }
        if (min > max) {
            throw new ArgumentException("min must be <= max.");       
        }
        Min = min;
        Max = max;
    }

    public Bounds(ValueT min, ValueT max, DummyRecord allowNegativeValues)
    {
        if (min > max) {
            throw new ArgumentException("min must be <= max.");       
        }
        Min = min;
        Max = max;
    }

    public readonly ValueT Min;
    public readonly ValueT Max;
}