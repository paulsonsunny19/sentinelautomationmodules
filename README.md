# STAT Next

A secure-by-default modernization of the Microsoft Sentinel Triage AssistanT concept.

STAT Next is a new implementation rather than a deployment wrapper around the legacy STAT Function package.

## Design goals

- System Assigned Managed Identity for runtime authentication.
- No application client secrets.
- No GitHub-release `WEBSITE_RUN_FROM_PACKAGE` bootstrap chain.
- Least-privilege, module-specific permissions.
- Native Microsoft Sentinel and Log Analytics modules first.
- Microsoft Graph / Entra / Defender integrations are optional modules.
- HTTPS only, TLS 1.2+, basic publishing disabled.
- Infrastructure as code using Bicep.
- Application code built and deployed through CI/CD rather than ARM downloading binaries.
- Structured JSON responses with correlation IDs and auditable module execution.

## Initial modules

1. `health` — service and identity health.
2. `sentinel/incident` — retrieve Sentinel incident context.
3. `sentinel/alerts` — retrieve alerts associated with an incident.
4. `sentinel/related-alerts` — Log Analytics/KQL based related-alert enrichment.

See `docs/ARCHITECTURE.md` and `docs/SECURITY.md`.
