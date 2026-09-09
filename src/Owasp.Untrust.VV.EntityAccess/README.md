# OWASP Untrust VV Entity Access

`Owasp.Untrust.VV.EntityAccess` provides the Pending → Ready path for entity IDs that must be resolved and authorized before use. It depends on VV core and ValueDescriptors, but not on ASP.NET, database frameworks, vaults, or a particular authorization product.

`EntityResolutionCandidate` parses and locally validates an ID without exposing it. Its resolution methods combine repository access with ownership/grant or policy checks and return an `AuthorizedEntity` only after authorization succeeds. The module contains the subject, repository, relationship, scope, action, and failure-disclosure contracts required to define this flow.

The module is an official VV friend assembly solely so its generic candidate base can mint opaque local-validation evidence. Application assemblies cannot construct that evidence or manufacture an authorized entity from an arbitrary ID.
