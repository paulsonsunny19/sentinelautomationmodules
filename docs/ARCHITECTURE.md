# STAT Next architecture

STAT Next separates infrastructure deployment from application deployment.

```text
Sentinel Playbook / Logic App
          |
          v
     STAT Next API
   Azure Function v4
 System Assigned Identity
          |
   +------+-------------------+
   |                          |
Sentinel ARM             Log Analytics
incidents/alerts         Related Alerts
   |
optional modules
   +-- Microsoft Graph / Entra
   +-- Defender XDR
   +-- Defender for Endpoint
   +-- Threat Intelligence
```

## Key differences from legacy STAT

- Application source is maintained in this repository.
- ARM/Bicep does not download application packages from GitHub releases.
- CI/CD deploys application code after infrastructure exists.
- Each integration is a module with an explicit permission profile.
- API requests are structured. Callers do not submit arbitrary KQL.
- Managed identity is the default runtime identity.
- Related Alerts uses Azure Monitor Query SDK rather than a hand-built REST authentication layer.
