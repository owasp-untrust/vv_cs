; Unshipped analyzer release

### New Rules

Rule ID | Category | Severity | Notes
--------|----------|----------|------
VV2001 | Owasp.Untrust.VV.Security | Error | Concrete validated-value leaves must be sealed
VV2002 | Owasp.Untrust.VV.Security | Error | CRTP self types must be exact
VV2003 | Owasp.Untrust.VV.Security | Error | Concrete validated-value constructors must be private
VV2004 | Owasp.Untrust.VV.Security | Error | Validated values cannot expose mutable or raw public state
VV2005 | Owasp.Untrust.VV.Security | Error | Raw escape hatches must be named ExposeUnchecked
VV2006 | Owasp.Untrust.VV.Security | Error | Cross-validated receivers cannot be request-parseable
VV2007 | Owasp.Untrust.VV.Security | Error | Cross-validation candidates cannot expose raw state
