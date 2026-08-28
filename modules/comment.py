from __future__ import annotations
from html import escape
from typing import Any

def _plain(value: Any) -> str:
    if value is None or value == "": return "None"
    if isinstance(value, list): return ", ".join(str(x) for x in value) if value else "None"
    return str(value).replace("\r", " ").replace("\n", " ")
def _html(value: Any) -> str: return escape(_plain(value), quote=True)
def _raw(item):
    raw=item.get("RawEntity"); return raw if isinstance(raw,dict) else item
def _additional(raw):
    data=raw.get("additionalData") or raw.get("AdditionalData"); return data if isinstance(data,dict) else {}
def _first(*values):
    for value in values:
        if value is not None and value != "": return value
    return None
class _SafeHtml(str): pass
def _html_table(headers,rows):
    if not rows:return ""
    head="".join(f"<th>{_html(h)}</th>" for h in headers);body=[]
    for row in rows:
        cells=[f"<td>{v}</td>" if isinstance(v,_SafeHtml) else f"<td>{_html(v)}</td>" for v in row];body.append("<tr>"+"".join(cells)+"</tr>")
    return "<table><thead><tr>"+head+"</tr></thead><tbody>"+"".join(body)+"</tbody></table>"
def _vertical_table(rows):return _html_table(["Field","Value"],[[f,v] for f,v in rows])
def _portal_user(upn,user_id):
    if not upn:return None
    if not user_id:return _SafeHtml(_html(upn))
    return _SafeHtml(f'<a href="https://portal.azure.com/#view/Microsoft_AAD_UsersAndTenants/UserProfileMenuBlade/~/overview/userId/{escape(str(user_id),quote=True)}" target="_blank">{_html(upn)}</a><br>(Contact User)')
def _mailto(upn):
    if not upn:return None
    safe=escape(str(upn),quote=True);return _SafeHtml(f'<a href="mailto:{safe}" target="_blank">{_html(upn)}</a>')
def _warnings(module):
    values=module.get("EnrichmentWarnings") or [];return "; ".join(str(x) for x in values) if values else "No enrichment warnings"
def _context(module,count_keys):
    parts=[]
    for key,label in count_keys:
        value=module.get(key)
        if value not in (None,""):parts.append(f"{label}: {value}")
    warnings=module.get("EnrichmentWarnings") or []
    if warnings:parts.append("Warnings: "+"; ".join(str(x) for x in warnings[:3]))
    return "; ".join(parts) if parts else "No additional findings"

def build_comment(base,scoring,aad=None,related=None,ti=None,mde=None,ueba=None,file_insights=None,mcas=None):
    aad,related,ti,mde,ueba,file_insights,mcas=[x if isinstance(x,dict) else {} for x in (aad,related,ti,mde,ueba,file_insights,mcas)]
    score=scoring.get("TotalScore",0);degraded=bool(aad.get('RiskUserAvailable') is False or aad.get('RiskEventsAvailable') is False or related.get('EnrichmentWarnings') or ueba.get('EnrichmentWarnings'))
    score_label=f"{score} (partial enrichment)" if degraded else score
    sections=[f"<h2>STAT Next Triage</h2><p><strong>Risk Score:</strong> {_html(score_label)}<br><strong>Entities Analyzed:</strong> {_html(base.get('EntitiesCount',0))}</p>"]
    details=[x for x in aad.get("DetailedResults",[]) if isinstance(x,dict)];risk_by_upn={str(x.get("UserPrincipalName","")).lower():x for x in details};risk_by_id={str(x.get("UserId","")).lower():x for x in details if x.get("UserId")};account_sections=[];accounts=base.get("Accounts",[])
    for index,item in enumerate(accounts,start=1):
        r=_raw(item);a=_additional(r);upn=_first(a.get("UserPrincipalName"),a.get("userPrincipalName"),r.get("userPrincipalName"),r.get("upn"),item.get("UserPrincipalName"));uid=_first(r.get("aadUserId"),r.get("objectGuid"),a.get("AadUserId"),a.get("aadUserId"),item.get("AADUserId"));risk=risk_by_upn.get(str(upn or "").lower()) or risk_by_id.get(str(uid or "").lower()) or {}
        rows=[("UserPrincipalName",_portal_user(upn,uid)),("City",_first(risk.get("City"),a.get("City"),a.get("city"),r.get("city"))),("Country",_first(risk.get("Country"),a.get("Country"),a.get("country"),r.get("country"))),("Department",_first(a.get("Department"),a.get("department"),r.get("department"),risk.get("Department"))),("JobTitle",_first(a.get("JobTitle"),a.get("jobTitle"),r.get("jobTitle"),risk.get("JobTitle"))),("Office",_first(a.get("OfficeLocation"),a.get("officeLocation"),r.get("officeLocation"),risk.get("Office"))),("AADRoles",risk.get("AADRoles")),("ManagerUPN",_mailto(risk.get("ManagerUPN"))),("MfaRegistered",risk.get("MfaRegistered")),("SSPREnabled",risk.get("SSPREnabled")),("SSPRRegistered",risk.get("SSPRRegistered")),("UserRiskLevel",risk.get("UserRiskLevel")),("UserRiskState",risk.get("UserRiskState")),("UserRiskDetail",risk.get("UserRiskDetail")),("RiskEvents",risk.get("RiskEventCount",0) if risk.get('RiskEventsAvailable',True) else 'Unavailable'),("FailedMFA",risk.get("UserFailedMFACount")),("MFAFraud",risk.get("UserMFAFraudCount"))]
        account_sections.append(f"<h4>{'Account' if len(accounts)==1 else f'Account {index}'}</h4>"+_vertical_table(rows))
    if account_sections:sections.append("<h3>Account Info</h3>"+"".join(account_sections))
    ip_rows=[]
    for item in base.get("IPs",[]):
        r=_raw(item);geo=item.get("GeoData") if isinstance(item.get("GeoData"),dict) else {};ip_rows.append([item.get("Address") or r.get("address"),geo.get("city"),geo.get("state"),geo.get("country"),geo.get("organization"),geo.get("organizationType"),geo.get("asn")])
    if ip_rows:sections.append("<h3>IP Info</h3>"+_html_table(["IP","City","State","Country","Organization","OrganizationType","ASN"],ip_rows))
    events=[x for x in aad.get("RiskEvents",[]) if isinstance(x,dict)]
    if events:
        rows=[[_mailto(e.get("UserPrincipalName")),e.get("RiskEventType"),e.get("RiskLevel"),e.get("RiskState"),e.get("RiskDetail"),e.get("Activity"),e.get("IPAddress"),e.get("DetectedDateTime")] for e in events[:20]];sections.append("<h3>Entra ID Protection - Risky Events</h3>"+_html_table(["User","Risk Event","Level","State","Detail","Activity","IP Address","Detected"],rows))
    elif aad.get('RiskEventsAvailable') is False or aad.get('RiskUserAvailable') is False:sections.append("<h3>Entra ID Protection - Risky Events</h3><p><strong>Enrichment unavailable.</strong> "+_html(_warnings(aad))+"</p>")
    else:sections.append("<h3>Entra ID Protection - Risky Events</h3><p>No Entra ID Protection risk detections returned for the analyzed incident users.</p>")
    hosts=[]
    for item in base.get("Hosts",[]):r=_raw(item);hosts.append([item.get("Hostname"),item.get("DnsDomain"),item.get("FQDN"),r.get("mdatpDeviceId") or r.get("MdatpDeviceId"),r.get("lastIpAddress") or r.get("LastIpAddress"),r.get("lastExternalIpAddress") or r.get("LastExternalIpAddress")])
    if hosts:sections.append("<h3>Host Info</h3>"+_html_table(["Host","Domain","FQDN","MDE Device ID","Last IP","External IP"],hosts))
    hashes=[]
    for item in base.get("FileHashes",[]):r=_raw(item);hashes.append([r.get("algorithm") or r.get("Algorithm") or item.get("Algorithm"),r.get("value") or r.get("Value") or r.get("hashValue") or item.get("HashValue")])
    if hashes:sections.append("<h3>File Hash Info</h3>"+_html_table(["Algorithm","Hash"],hashes))
    files=[]
    for item in base.get("Files",[]):r=_raw(item);files.append([r.get("fileName") or r.get("FileName") or r.get("name") or item.get("Name"),r.get("directory") or r.get("Directory") or r.get("path") or r.get("Path") or item.get("Directory")])
    if files:sections.append("<h3>File Info</h3>"+_html_table(["File","Path"],files))
    module_rows=[["AAD / Identity Risk",f"User risk: {aad.get('HighestRiskLevel','unknown')}; risk events: {aad.get('RiskEventCount',0) if aad.get('RiskEventsAvailable',True) else 'Unavailable'}; failed MFA: {aad.get('FailedMFATotalCount',0)}; fraud: {aad.get('MFAFraudTotalCount',0)}",_warnings(aad)],["Related Alerts",related.get("RelatedAlertsCount",0),_context(related,[("RelatedAlertsCount","Related alerts")])],["Threat Intelligence",ti.get("MatchedTIItemCount",0),_context(ti,[("MatchedTIItemCount","TI matches")])],["MDE",mde.get("AnalyzedEntities",mde.get("MachineCount",0)),_context(mde,[("AnalyzedEntities","Entities"),("MachineCount","Machines")])],["UEBA",ueba.get("AnomalyCount",0),_context(ueba,[("AnomalyCount","Anomalies")])],["File Insights",file_insights.get("HashesLinkedToThreatCount",0),_context(file_insights,[("HashesLinkedToThreatCount","Threat-linked hashes")])]]
    if mcas and not mcas.get('ConfigurationRequired'):module_rows.append(["Defender for Cloud Apps",mcas.get("AnalyzedEntities",mcas.get("MatchedCount",0)),_context(mcas,[("AnalyzedEntities","Entities"),("MatchedCount","Matches")])])
    elif mcas.get('ConfigurationRequired'):module_rows.append(["Defender for Cloud Apps","Disabled / not configured",mcas.get('ConfigurationMessage')])
    sections.append("<h3>Enrichment Summary</h3>"+_html_table(["Module","Result","Context"],module_rows));sections.append("<p><em>Generated by STAT Next using the Microsoft Sentinel incident payload and configured enrichment modules.</em></p>")
    return {"ModuleName":"STATComment","Message":"".join(sections),"RiskScore":score,"PartialEnrichment":degraded}
