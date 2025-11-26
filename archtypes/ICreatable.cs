namespace Owasp.Untrust.VV.Archetypes;

public interface ICreatable<TWrapper, ValueT>
{
    static abstract TWrapper CreateNonValidated(ValueT valueToWrap); 
}
