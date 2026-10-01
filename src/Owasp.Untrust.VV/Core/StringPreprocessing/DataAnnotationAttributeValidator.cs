using System.ComponentModel.DataAnnotations;
using System.Text;
using Owasp.Untrust.VV.Core;

namespace Owasp.Untrust.VV.Core.StringPreprocessing;

public readonly struct DataAnnotationAttributeValidator<TAttribute> : IStringValidator
    where TAttribute : ValidationAttribute, new()
{
    private static readonly TAttribute Attribute = new();
    private static readonly string DataTypeName = GetDataTypeName();

    public ValidationIssue? ValidateString(string value) =>
        Attribute.IsValid(value)
            ? null
            : new ValidationIssue(
                $"{DataTypeName.Replace(' ', '.')}.format",
                $"The value is not a valid {DataTypeName}.");

    private static string GetDataTypeName()
    {
        const string attributeSuffix = "Attribute";
        string typeName = typeof(TAttribute).Name;
        string name = typeName[..^attributeSuffix.Length];
        var result = new StringBuilder(name.Length + 4);

        for (int index = 0; index < name.Length; index++)
        {
            char character = name[index];
            if (index > 0 && char.IsUpper(character))
            {
                result.Append(' ');
            }

            result.Append(char.ToLowerInvariant(character));
        }

        return result.ToString();
    }
}
