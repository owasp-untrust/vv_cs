namespace Owasp.Untrust.VV.Core;

[AttributeUsage(AttributeTargets.Class, AllowMultiple = false, Inherited = false)]
public sealed class ValidatedFromTraitsAttribute<TTraits, TDisclosure> : Attribute;
