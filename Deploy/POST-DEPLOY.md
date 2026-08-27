# Post deployment

1. Confirm the STAT Function App exists and has System Assigned managed identity enabled.
2. Confirm `SentinelTriageAssistantv2` / `STAT v2` custom connector exists.
3. Run the official upstream `GrantPermissions.ps1` procedure for the Function identity.
4. Allow Azure/Entra permission propagation.
5. Test the Base module before testing Related Alerts.
6. If Related Alerts returns HTTP 403 from Log Analytics, verify the managed identity's workspace/Sentinel RBAC assignments.
