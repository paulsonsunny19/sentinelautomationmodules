# STAT Next portal deployment

STAT Next is intended to deploy from Azure Portal in the same general user experience as legacy STAT. GitHub Actions are validation-only and are not the production deployment mechanism.

## User inputs

- Target resource group / Azure region (Azure deployment basics)
- STAT Next name prefix
- Microsoft Sentinel resource group
- Microsoft Sentinel Log Analytics workspace name

The deployment creates the Function infrastructure, System Assigned Managed Identity, monitoring, secure host storage configuration, and workspace-scoped RBAC.

## Application payload

The application payload must be published as a deterministic deployment artifact that Azure can consume without a redirect and without a user-provided SAS URL. The final packaging mechanism will be implemented before the Deploy to Azure link is declared ready. We will not reintroduce the legacy GitHub-release redirect pattern or require a CI/CD deployment pipeline.

## Security

The Portal deployment must not request Graph, Exchange, Entra Risk, or Defender application permissions unless those optional modules are explicitly selected in a future release.
