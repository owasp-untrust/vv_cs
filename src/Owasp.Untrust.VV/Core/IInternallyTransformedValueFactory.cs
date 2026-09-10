#pragma warning disable CS1591

namespace Owasp.Untrust.VV.Core;

public interface IInternallyTransformedValueFactory<TSelf, TOutput>
    where TOutput : notnull
{
    static abstract TSelf CreateTransformed(InternallyTransformedValue<TOutput, TSelf> transformed);
}
