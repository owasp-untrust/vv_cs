namespace Owasp.Untrust.VV.Archetypes;

public interface ICreatable<WrapperT, ValueT>
{
    static abstract WrapperT CreateNonValidated(ValueT valueToWrap); 
}
