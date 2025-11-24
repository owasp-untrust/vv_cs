using System.ComponentModel.DataAnnotations;

namespace Owasp.Untrust.VV.Foundation;

public interface ICreatable<WrapperT, ValueT>
{
    static abstract WrapperT CreateNonValidated(ValueT valueToWrap); 
}
