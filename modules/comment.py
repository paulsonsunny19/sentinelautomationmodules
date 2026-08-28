from __future__ import annotations
from typing import Any


def _v(value: Any) -> str:
    if value is None or value == "": return "None"
    if isinstance(value,list): value = "[" + ", ".join(str(x) for x in value) + "]"
    return str(value).replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _raw(item: dict[str, Any]) -> dict[str, Any]:
    raw=item.get("RawEntity"); return raw if isinstance(raw,dict) else item


def _additional(raw: dict[str, Any]) -> dict[str, Any]:
    data=raw.get("additionalData") or raw.get("AdditionalData"); return data if isinstance(data,dict) else {}


def _first(*values: Any) -> Any:
    for value in values:
        if value is not None and value != "": return value
    return None


def _table(headers: list[str], rows: list[list[Any]]) -> str:
    if not rows: return ""
    head="| " + " | ".join(headers) + " |"; sep="| " + " | ".join(["---"]*len(headers)) + " |"
    body=["| " + " | ".join(_v(x) for x in row) + " |" for row in rows]
    return "\n".join([head,sep,*body])


def _vertical_table(rows: list[tuple[str, Any]]) -> str:
    return _table(["Field", "Value"], [[field, value] for field, value in rows])


def _portal_user(upn: Any,user_id: Any) -> str | None:
    if not upn: return None
    if not user_id: return str(upn)
    return f'<a href="https://portal.azure.com/#view/Microsoft_AAD_UsersAndTenants/UserProfileMenuBlade/~/overview/userId/{user_id}" target="_blank">{upn}</a><br>(Contact User)'


def _mailto(upn: Any) -> str | None:
    return f'<a href="mailto:{upn}" target="_blank">{upn}</a>' if upn else None


def build_comment(base: dict[str, Any], scoring: dict[str, Any], aad: dict[str, Any] | None = None,
                  related: dict[str, Any] | None = None, ti: dict[str, Any] | None = None,
                  mde: dict[str, Any] | None = None, ueba: dict[str, Any] | None = None,
                  file_insights: dict[str, Any] | None = None, mcas: dict[str, Any] | None = None) -> dict[str, Any]:
    aad,related,ti,mde,ueba,file_insights,mcas=[x if isinstance(x,dict) else {} for x in (aad,related,ti,mde,ueba,file_insights,mcas)]
    score=scoring.get("TotalScore",0)
    sections=[f"## STAT Next Triage\n\n**Risk Score:** {_v(score)}  \n**Entities Analyzed:** {_v(base.get('EntitiesCount',0))}"]

    account_sections=[]
    details=[x for x in aad.get("DetailedResults",[]) if isinstance(x,dict)]
    risk_by_upn={str(x.get("UserPrincipalName","")).lower():x for x in details}
    risk_by_id={str(x.get("UserId","")).lower():x for x in details if x.get("UserId")}
    for index,item in enumerate(base.get("Accounts",[]),start=1):
        r=_raw(item); a=_additional(r)
        upn=_first(a.get("UserPrincipalName"),a.get("userPrincipalName"),r.get("userPrincipalName"),r.get("upn"),item.get("UserPrincipalName"))
        uid=_first(r.get("aadUserId"),r.get("objectGuid"),a.get("AadUserId"),a.get("aadUserId"))
        risk=risk_by_upn.get(str(upn or "").lower()) or risk_by_id.get(str(uid or "").lower()) or {}
        rows=[
            ("UserPrincipalName",_portal_user(upn,uid)),
            ("City",_first(risk.get("City"),a.get("City"),a.get("city"),r.get("city"))),
            ("Country",_first(risk.get("Country"),a.get("Country"),a.get("country"),r.get("country"))),
            ("Department",_first(a.get("Department"),a.get("department"),r.get("department"),risk.get("Department"))),
            ("JobTitle",_first(a.get("JobTitle"),a.get("jobTitle"),r.get("jobTitle"),risk.get("JobTitle"))),
            ("Office",_first(a.get("OfficeLocation"),a.get("officeLocation"),r.get("officeLocation"),risk.get("Office"))),
            ("AADRoles",risk.get("AADRoles")),
            ("ManagerUPN",_mailto(risk.get("ManagerUPN"))),
            ("MfaRegistered",risk.get("MfaRegistered")),
            ("SSPREnabled",risk.get("SSPREnabled")),
            ("SSPRRegistered",risk.get("SSPRRegistered")),
            ("RiskLevel",risk.get("UserRiskLevel")),
            ("FailedMFA",risk.get("UserFailedMFACount")),
            ("MFAFraud",risk.get("UserMFAFraudCount")),
        ]
        heading="#### Account" if len(base.get("Accounts",[])) == 1 else f"#### Account {index}"
        account_sections.append(heading+"\n\n"+_vertical_table(rows))
    if account_sections:
        sections.append("### Account Info\n\n"+"\n\n".join(account_sections))

    ips=[]
    for item in base.get("IPs",[]):
        r=_raw(item); ips.append([item.get("Address") or r.get("address"),r.get("location") or r.get("countryCode"),r.get("friendlyName")])
    if ips: sections.append("### IP Info\n\n"+_table(["IP","Location","Name"],ips))

    hosts=[]
    for item in base.get("Hosts",[]):
        r=_raw(item); hosts.append([item.get("Hostname"),item.get("DnsDomain"),item.get("FQDN"),r.get("mdatpDeviceId") or r.get("MdatpDeviceId"),r.get("lastIpAddress") or r.get("LastIpAddress"),r.get("lastExternalIpAddress") or r.get("LastExternalIpAddress")])
    if hosts: sections.append("### Host Info\n\n"+_table(["Host","Domain","FQDN","MDE Device ID","Last IP","External IP"],hosts))

    hashes=[]
    for item in base.get("FileHashes",[]):
        r=_raw(item); hashes.append([r.get("algorithm") or r.get("Algorithm"),r.get("value") or r.get("Value") or r.get("hashValue")])
    if hashes: sections.append("### File Hash Info\n\n"+_table(["Algorithm","Hash"],hashes))

    files=[]
    for item in base.get("Files",[]):
        r=_raw(item); files.append([r.get("fileName") or r.get("FileName") or r.get("name"),r.get("directory") or r.get("Directory") or r.get("path") or r.get("Path")])
    if files: sections.append("### File Info\n\n"+_table(["File","Path"],files))

    sections.append("### Enrichment Summary\n\n"+_table(["Module","Result"],[
        ["AAD / Identity Risk",f"Highest risk: {aad.get('HighestRiskLevel','unknown')}; failed MFA: {aad.get('FailedMFATotalCount',0)}; fraud: {aad.get('MFAFraudTotalCount',0)}"],
        ["Related Alerts",related.get("RelatedAlertsCount",0)],["Threat Intelligence",ti.get("MatchedTIItemCount",0)],
        ["MDE",mde.get("AnalyzedEntities",mde.get("MachineCount",0))],["UEBA",ueba.get("AnomalyCount",0)],
        ["File Insights",file_insights.get("HashesLinkedToThreatCount",0)],["Defender for Cloud Apps",mcas.get("AnalyzedEntities",mcas.get("MatchedCount",0))]]))
    sections.append("_Generated by STAT Next using the Microsoft Sentinel incident payload and configured enrichment modules._")
    return {"ModuleName":"STATComment","Message":"\n\n".join(sections),"RiskScore":score}
