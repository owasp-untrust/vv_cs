using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.Security;

namespace Owasp.Untrust.VV.Core;

[EditorBrowsable(EditorBrowsableState.Never)]
[Obsolete("Do not use!", true)]
public interface __IWrappableForOptional<WrapperT>
    where WrapperT : __IWrappableForOptional<WrapperT>
{
    [EditorBrowsable(EditorBrowsableState.Never)]
    static abstract bool __TryWrapBypassingCompileTimeValueTypeCheck(object valueAsObj, out WrapperT result);
}
