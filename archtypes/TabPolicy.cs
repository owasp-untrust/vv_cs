namespace Owasp.Untrust.VV.Archetypes;

public interface TabPolicy 
{
    abstract static bool AllowTab();
}

public class AcceptTab : TabPolicy 
{
    public static bool AllowTab() { return true; }
}

public class RejectTab : TabPolicy 
{
    public static bool AllowTab() { return false; }
}
