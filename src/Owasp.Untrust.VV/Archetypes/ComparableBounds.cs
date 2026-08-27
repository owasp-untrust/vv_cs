namespace Owasp.Untrust.VV.Archetypes;

/// <summary>Inclusive bounds for any totally ordered domain value, including dates.</summary>
public readonly record struct ComparableBounds<TValue>
    where TValue : notnull, IComparable<TValue>
{
    public ComparableBounds(TValue minimum, TValue maximum)
    {
        if (minimum.CompareTo(maximum) > 0)
        {
            throw new ArgumentOutOfRangeException(nameof(minimum), "Minimum must not exceed maximum.");
        }

        Minimum = minimum;
        Maximum = maximum;
    }

    public TValue Minimum { get; }

    public TValue Maximum { get; }

    public bool Contains(TValue value) =>
        value.CompareTo(Minimum) >= 0 && value.CompareTo(Maximum) <= 0;
}
