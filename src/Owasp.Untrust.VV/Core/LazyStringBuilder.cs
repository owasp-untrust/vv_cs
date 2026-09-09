using System;
using System.Collections.Generic;
using System.Text;
using Owasp.Untrust.ValueDescriptors;
using Owasp.Untrust.ValueDescriptors.Core;

namespace Owasp.Untrust.VV.Core;

/// <summary>
/// Builds an outbound payload from code-owned text and validated values.
/// Its string representation deliberately uses each value's VV-selected public
/// representation, while <see cref="ExposeUnchecked"/> is the single explicit
/// boundary at which the transport payload becomes available.
/// </summary>
public sealed class LazyStringBuilder
{
    private static readonly Func<string, string> IDENTITY_TRANSFORM = value => value;
    private readonly Func<string, string> _defaultTransform;
    private readonly List<ISegment> _segments = new List<ISegment>();

    public LazyStringBuilder()
        : this(IDENTITY_TRANSFORM)
    {
    }

    /// <param name="encodeValue">Encoding applied separately to every exposed validated value.</param>
    public LazyStringBuilder(Func<string, string> encodeValue)
    {
        _defaultTransform = encodeValue ?? throw new ArgumentNullException(nameof(encodeValue));
    }

    private LazyStringBuilder(LazyStringBuilder source)
    {
        _defaultTransform = source._defaultTransform;
        _segments.AddRange(source._segments);
    }

    /// <summary>Starts a payload with code-owned text.</summary>
    public static LazyStringBuilder From(Hardcoded value)
    {
        return new LazyStringBuilder().Append(value);
    }

    /// <summary>Starts a payload with a validated value.</summary>
    public static LazyStringBuilder From(IExposableValidatedValue<string> value)
    {
        return new LazyStringBuilder().Append(value);
    }

    // Only safe segment types participate in concatenation. In particular, there
    // deliberately is no PiiConcat + string or string + PiiConcat overload.
    public static LazyStringBuilder operator +(LazyStringBuilder left, Hardcoded right)
    {
        if (left == null) throw new ArgumentNullException(nameof(left));
        return new LazyStringBuilder(left).Append(right);
    }

    public static LazyStringBuilder operator +(Hardcoded left, LazyStringBuilder right)
    {
        if (right == null) throw new ArgumentNullException(nameof(right));
        LazyStringBuilder result = new LazyStringBuilder(right);
        return result.PushPrefix(left);
    }

    public static LazyStringBuilder operator +(LazyStringBuilder left, IExposableValidatedValue<string> right)
    {
        if (left == null) throw new ArgumentNullException(nameof(left));
        return new LazyStringBuilder(left).Append(right);
    }

    public static LazyStringBuilder operator +(IExposableValidatedValue<string> left, LazyStringBuilder right)
    {
        if (right == null) throw new ArgumentNullException(nameof(right));
        LazyStringBuilder result = new LazyStringBuilder(right);
        result._segments.Insert(0, new ValidatedValueSegment(left, result._defaultTransform));
        return result;
    }

    /// <summary>Appends text explicitly declared as originating in program code.</summary>
    public LazyStringBuilder Append(Hardcoded value)
    {
        if (value == null) throw new ArgumentNullException(nameof(value));

        _segments.Add(new HardcodedSegment(value));
        return this;
    }

    /// <summary>Prepends code-owned text, such as a form parameter name.</summary>
    public LazyStringBuilder PushPrefix(Hardcoded value)
    {
        if (value == null) throw new ArgumentNullException(nameof(value));

        _segments.Insert(0, new HardcodedSegment(value));
        return this;
    }

    /// <summary>
    /// Appends a validated string. The configured encoder is applied to its raw
    /// value only in the private outbound representation.
    /// </summary>
    public LazyStringBuilder Append(IExposableValidatedValue<string> value)
    {
        return Append(value, _defaultTransform);
    }

    /// <summary>
    /// Appends a validated string using a transform selected for this individual
    /// value. The value and transform stay together until the payload is
    /// explicitly exposed, so the raw value is never returned to the caller.
    /// This is appropriate for wire representation changes such as XML escaping,
    /// URL-component encoding, or provider-specific phone formatting; it is not
    /// a replacement for a domain-value transformation and revalidation.
    /// </summary>
    public LazyStringBuilder Append(IExposableValidatedValue<string> value, Func<string, string> transform)
    {
        if (value == null) throw new ArgumentNullException(nameof(value));
        if (transform == null) throw new ArgumentNullException(nameof(transform));

        _segments.Add(new ValidatedValueSegment(value, transform));
        return this;
    }

    /// <summary>
    /// Explicitly crosses the payload boundary for the HTTP client. Do not log
    /// this result; log this builder instead to use VV redaction/masking.
    /// </summary>
    public string ExposeUnchecked()
    {
        StringBuilder payload = new StringBuilder();
        foreach (ISegment segment in _segments)
        {
            payload.Append(segment.ExposeUnchecked());
        }
        return payload.ToString();
    }

    /// <summary>Returns a payload representation with VV disclosure policies enforced.</summary>
    public override string ToString()
    {
        StringBuilder publicRepresentation = new StringBuilder();
        foreach (ISegment segment in _segments)
        {
            publicRepresentation.Append(segment.ToPublicString());
        }
        return publicRepresentation.ToString();
    }

    private interface ISegment
    {
        string ExposeUnchecked();

        string ToPublicString();
    }

    private sealed class HardcodedSegment : ISegment
    {
        private readonly Hardcoded _value;

        public HardcodedSegment(Hardcoded value)
        {
            _value = value;
        }

        public string ExposeUnchecked()
        {
            return _value.ExposeUnchecked();
        }

        public string ToPublicString()
        {
            return _value.ToPublicString();
        }
    }

    private sealed class ValidatedValueSegment : ISegment
    {
        private readonly IExposableValidatedValue<string> _value;
        private readonly Func<string, string> _transform;

        public ValidatedValueSegment(IExposableValidatedValue<string> value, Func<string, string> transform)
        {
            _value = value;
            _transform = transform;
        }

        public string ExposeUnchecked()
        {
            string transformed = _transform(_value.ExposeUnchecked());
            return transformed ?? throw new InvalidOperationException("The configured transform returned null.");
        }

        public string ToPublicString()
        {
            return _value.ToPublicString();
        }
    }
}
