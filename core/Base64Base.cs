using System;
using Owasp.Untrust.VV.Archetypes;

namespace Owasp.Untrust.VV.Core;

/// <summary>
/// Core building block for validated Base64 values.
/// Inherit from this type to create concrete Base64 validated values.
/// </summary>
/// <typeparam name="TWrapper">
/// The concrete wrapper type, e.g. <c>MyBase64Token : Base64Base&lt;MyBase64Token&gt;</c>.
/// </typeparam>
public abstract class Base64Base<TWrapper, TVariant> : BoundedAnyContentStringBase<TWrapper>
    where TWrapper : Base64Base<TWrapper, TVariant>, ICreatable<TWrapper, string>
    where TVariant : Base64Variant
{
    /// <summary>
    /// Decodes the Base64 value into a new byte array.
    /// </summary>
    public byte[] ToBytes()
    {
        // Value is already validated in NormalizeAndValidate.
        return Convert.FromBase64String(Value);
    }

    protected override ValidationResultHolder ChainableValidation()
    {
        ValidationResultHolder result = base.ChainableValidation();
        if (result.IsValid) 
        {
            if (string.IsNullOrWhiteSpace(Value))
            {
                result.Invalidate();
            }
            else 
            {
                // Length must be a multiple of 4 for standard Base64.
                if ((Value.Length & 3) != 0)
                {
                    result.Invalidate();
                }
                else if (!TVariant.Regex().IsMatch(Value)) 
                {
                    result.Invalidate();
                }
            }
        }
        return result;
    }
}
