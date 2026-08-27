from __future__ import annotations
from typing import Any

VERSIONS = {"BaseModule":"0.4.0","AADRisksModule":"0.0.4","FileModule":"0.0.3","KQLModule":"0.0.5","MCASModule":"0.0.5","MDEModule":"0.1.1","OOFModule":"0.0.3","RelatedAlerts":"0.0.7","TIModule":"0.0.4","UEBAModule":"0.0.5","WatchlistModule":"0.0.5"}


def normalize(entities: list[dict[str, Any]], incident_arm_id: str, workspace_id: str, tenant_id: str | None = None, tenant_display_name: str | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"Accounts":[],"IPs":[],"Hosts":[],"Files":[],"FileHashes":[],"Domains":[],"URLs":[],"OtherEntities":[],"IncidentARMId":incident_arm_id,"WorkspaceId":workspace_id,"TenantId":tenant_id,"TenantDisplayName":tenant_display_name,"ModuleVersions":VERSIONS,"ModuleName":"BaseModule"}
    mapping = {"account":"Accounts","ip":"IPs","host":"Hosts","file":"Files","filehash":"FileHashes","dnsdomain":"Domains","url":"URLs"}
    for entity in entities or []:
        kind = str(entity.get("kind") or entity.get("Kind") or entity.get("type") or "").split("/")[-1].lower()
        props = entity.get("properties") if isinstance(entity.get("properties"), dict) else entity
        bucket = mapping.get(kind)
        if not bucket:
            result["OtherEntities"].append(entity); continue
        if bucket == "Accounts": item = {**props, "RawEntity": props}
        elif bucket == "IPs": item = {"Address": props.get("address") or props.get("Address"), "RawEntity": props}
        elif bucket == "Hosts":
            host = props.get("hostName") or props.get("Hostname"); domain = props.get("dnsDomain") or props.get("DnsDomain")
            item = {"Hostname":host,"DnsDomain":domain,"FQDN": f"{host}.{domain}" if host and domain else host,"RawEntity":props}
        else: item = {"RawEntity": props}
        result[bucket].append(item)
    result["EntitiesCount"] = len(entities or [])
    for bucket in ("Accounts","IPs","Hosts","Files","FileHashes","Domains","URLs","OtherEntities"):
        result[f"{bucket}Count"] = len(result[bucket])
    return result
