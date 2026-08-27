#pragma warning disable CS1591

namespace Owasp.Untrust.VV.Archetypes;

/// <summary>An immutable inclusive range.</summary>
public readonly struct Bounds<TValue> : IEquatable<Bounds<TValue>>
{
    public Bounds(TValue minimum, TValue maximum)
    {
        if (Comparer<TValue>.Default.Compare(minimum, maximum) > 0)
        {
            throw new ArgumentException("Minimum must be less than or equal to maximum.");
        }

        Minimum = minimum;
        Maximum = maximum;
    }

    public TValue Minimum { get; }

    public TValue Maximum { get; }

    public bool Contains(TValue value) =>
        Comparer<TValue>.Default.Compare(value, Minimum) >= 0 &&
        Comparer<TValue>.Default.Compare(value, Maximum) <= 0;

    public bool Equals(Bounds<TValue> other) =>
        EqualityComparer<TValue>.Default.Equals(Minimum, other.Minimum) &&
        EqualityComparer<TValue>.Default.Equals(Maximum, other.Maximum);

    public override bool Equals(object? obj) => obj is Bounds<TValue> other && Equals(other);

    public override int GetHashCode() => HashCode.Combine(Minimum, Maximum);

    public static bool operator ==(Bounds<TValue> left, Bounds<TValue> right) => left.Equals(right);

    public static bool operator !=(Bounds<TValue> left, Bounds<TValue> right) => !left.Equals(right);
}
