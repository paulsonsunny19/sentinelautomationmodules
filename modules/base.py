from __future__ import annotations

from typing import Any


def _props(entity: dict[str, Any]) -> dict[str, Any]:
    value = entity.get("properties")
    return value if isinstance(value, dict) else entity


def _kind(entity: dict[str, Any]) -> str:
    return str(entity.get("kind") or _props(entity).get("kind") or "").lower()


def _raw(entity: dict[str, Any]) -> dict[str, Any]:
    p = _props(entity)
    raw = dict(p)
    raw.pop("kind", None)
    return raw


def normalize_entities(entities: list[dict[str, Any]], incident_arm_id: str, workspace_id: str) -> dict[str, Any]:
    """Normalize Sentinel entities into the original STAT-style shared Base contract.

    External enrichments are deliberately not fabricated here.  Accounts and IPs carry
    stable placeholders/contracts so dedicated enrichment helpers can populate them.
    """
    accounts: list[dict[str, Any]] = []
    ips: list[dict[str, Any]] = []
    hosts: list[dict[str, Any]] = []
    files: list[dict[str, Any]] = []
    hashes: list[dict[str, Any]] = []
    domains: list[dict[str, Any]] = []
    urls: list[dict[str, Any]] = []
    other: list[dict[str, Any]] = []

    for entity in entities:
        if not isinstance(entity, dict):
            continue
        p = _props(entity)
        kind = _kind(entity)
        raw = _raw(entity)

        if kind == "account":
            upn = p.get("userPrincipalName") or p.get("upn") or p.get("friendlyName")
            accounts.append({
                "UserPrincipalName": upn,
                "AADUserId": p.get("aadUserId") or p.get("id"),
                "Name": p.get("accountName") or p.get("name"),
                "NTDomain": p.get("ntDomain"),
                "RawEntity": raw,
            })
        elif kind in {"ip", "ipaddress"}:
            address = p.get("address") or p.get("ipAddress") or p.get("friendlyName")
            ips.append({"Address": address, "GeoData": {}, "RawEntity": raw})
        elif kind == "host":
            hostname = p.get("hostName") or p.get("hostname") or p.get("friendlyName")
            dns = p.get("dnsDomain")
            hosts.append({
                "Hostname": hostname,
                "DnsDomain": dns,
                "FQDN": f"{hostname}.{dns}" if hostname and dns else hostname,
                "RawEntity": raw,
            })
        elif kind == "file":
            files.append({
                "Name": p.get("fileName") or p.get("name") or p.get("friendlyName"),
                "Directory": p.get("directory"),
                "RawEntity": raw,
            })
        elif kind in {"filehash", "filehashvalue"}:
            hashes.append({
                "HashValue": p.get("hashValue") or p.get("value") or p.get("friendlyName"),
                "Algorithm": p.get("algorithm"),
                "RawEntity": raw,
            })
        elif kind in {"dnsresolution", "dnsdomain", "domain"}:
            domains.append({"DomainName": p.get("domainName") or p.get("friendlyName"), "RawEntity": raw})
        elif kind == "url":
            urls.append({"Url": p.get("url") or p.get("friendlyName"), "RawEntity": raw})
        else:
            other.append(entity)

    return {
        "IncidentARMId": incident_arm_id,
        "WorkspaceId": workspace_id,
        "EntitiesCount": len(entities),
        "Accounts": accounts,
        "AccountsCount": len(accounts),
        "IPs": ips,
        "IPsCount": len(ips),
        "Hosts": hosts,
        "HostsCount": len(hosts),
        "Files": files,
        "FilesCount": len(files),
        "FileHashes": hashes,
        "FileHashesCount": len(hashes),
        "Domains": domains,
        "DomainsCount": len(domains),
        "URLs": urls,
        "URLsCount": len(urls),
        "OtherEntities": other,
        "OtherEntitiesCount": len(other),
    }
