namespace Owasp.Untrust.VV.Archetypes;

public interface ICreatable<TWrapper, TValue>
{
    static abstract TWrapper CreateNonValidated(TValue valueToWrap); 
}
