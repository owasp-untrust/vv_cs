using System.Text.RegularExpressions;

namespace Owasp.Untrust.VV.Archetypes;

public interface Base64Variant 
{
    abstract static Regex Regex();
}

public class Standard : Base64Variant 
{
    private static Regex REGEX = new Regex("^[A-Za-z0-9+/]+={0,2}$;");
    public static Regex Regex() { return REGEX; }
}

public class UrlSafe : Base64Variant 
{
    private static Regex REGEX = new Regex("^[A-Za-z0-9_-]+={0,2}$;");
    public static Regex Regex() { return REGEX; }
}
