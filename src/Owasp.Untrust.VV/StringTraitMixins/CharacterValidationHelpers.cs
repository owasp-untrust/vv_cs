#pragma warning disable CS1591
namespace Owasp.Untrust.VV.StringTraitMixins;

internal static class CharacterValidationHelpers
{
    internal static bool IsWellFormedUnicodeWithoutDisallowedControls(
        string value,
        bool allowLineFeed,
        bool allowTab)
    {
        for (int index = 0; index < value.Length; index++)
        {
            char character = value[index];
            //var rune = Rune.GetRuneAt(value, index);
            if (char.IsHighSurrogate(character))
            {
                if (index + 1 >= value.Length || !char.IsLowSurrogate(value[index + 1]))
                {
                    return false;
                }

                index++;
                continue;
            }

            if (char.IsLowSurrogate(character))
            {
                return false;
            }

            if (char.IsControl(character) &&
                !(allowLineFeed && character == '\n') &&
                !(allowTab && character == '\t'))
            {
                return false;
            }
        }

        return true;
    }
}
