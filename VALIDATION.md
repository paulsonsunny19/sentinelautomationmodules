# Deployment validation checklist

After ARM reports success, confirm the resource group contains:

- Storage account named `stat<unique>` when default naming is used.
- Function App named `stat-<unique>` with System Assigned identity enabled.
- Custom API / Logic Apps connector `SentinelTriageAssistantv2` (display name `STAT v2`).
- Optional `Sample-STAT-Triage` Logic App when requested.

In the Function App configuration confirm `WEBSITE_RUN_FROM_PACKAGE` is the direct Azure Blob URL. Then complete the official STAT permission-granting procedure before testing modules such as Related Alerts.
