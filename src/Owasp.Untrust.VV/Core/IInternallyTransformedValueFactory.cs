#pragma warning disable CS1591

namespace Owasp.Untrust.VV.Core;

public interface IInternallyTransformedValueFactory<TSelf, TTransformedVal>
    where TTransformedVal : notnull
{
    static abstract TSelf CreateTransformed(InternallyTransformedValue<TSelf, TTransformedVal> transformed);
}
