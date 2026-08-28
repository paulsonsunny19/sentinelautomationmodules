from __future__ import annotations
from html import escape
from typing import Any


def _plain(value: Any) -> str:
    if value is None or value == "":
        return "None"
    if isinstance(value, list):
        return "[" + ", ".join(str(x) for x in value) + "]"
    return str(value).replace("\r", " ").replace("\n", " ")


def _html(value: Any) -> str:
    return escape(_plain(value), quote=True)


def _raw(item: dict[str, Any]) -> dict[str, Any]:
    raw = item.get("RawEntity")
    return raw if isinstance(raw, dict) else item


def _additional(raw: dict[str, Any]) -> dict[str, Any]:
    data = raw.get("additionalData") or raw.get("AdditionalData")
    return data if isinstance(data, dict) else {}


def _first(*values: Any) -> Any:
    for value in values:
        if value is not None and value != "":
            return value
    return None


def _html_table(headers: list[str], rows: list[list[Any]]) -> str:
    if not rows:
        return ""
    head = "".join(f"<th>{_html(h)}</th>" for h in headers)
    body = []
    for row in rows:
        cells = []
        for value in row:
            if isinstance(value, _SafeHtml):
                cells.append(f"<td>{value}</td>")
            else:
                cells.append(f"<td>{_html(value)}</td>")
        body.append("<tr>" + "".join(cells) + "</tr>")
    return "<table><thead><tr>" + head + "</tr></thead><tbody>" + "".join(body) + "</tbody></table>"


class _SafeHtml(str):
    pass


def _vertical_table(rows: list[tuple[str, Any]]) -> str:
    return _html_table(["Field", "Value"], [[field, value] for field, value in rows])


def _portal_user(upn: Any, user_id: Any) -> _SafeHtml | None:
    if not upn:
        return None
    if not user_id:
        return _SafeHtml(_html(upn))
    return _SafeHtml(
        f'<a href="https://portal.azure.com/#view/Microsoft_AAD_UsersAndTenants/UserProfileMenuBlade/~/overview/userId/{escape(str(user_id), quote=True)}" target="_blank">{_html(upn)}</a><br>(Contact User)'
    )


def _mailto(upn: Any) -> _SafeHtml | None:
    if not upn:
        return None
    safe = escape(str(upn), quote=True)
    return _SafeHtml(f'<a href="mailto:{safe}" target="_blank">{_html(upn)}</a>')


def _module_context(module: dict[str, Any], preferred: list[str]) -> str:
    for key in preferred:
        value = module.get(key)
        if value not in (None, "", [], {}):
            return _plain(value)
    message = module.get("Message") or module.get("Status") or module.get("Result")
    return _plain(message) if message not in (None, "") else "No additional findings"


def build_comment(base: dict[str, Any], scoring: dict[str, Any], aad: dict[str, Any] | None = None,
                  related: dict[str, Any] | None = None, ti: dict[str, Any] | None = None,
                  mde: dict[str, Any] | None = None, ueba: dict[str, Any] | None = None,
                  file_insights: dict[str, Any] | None = None, mcas: dict[str, Any] | None = None) -> dict[str, Any]:
    aad, related, ti, mde, ueba, file_insights, mcas = [x if isinstance(x, dict) else {} for x in (aad, related, ti, mde, ueba, file_insights, mcas)]
    score = scoring.get("TotalScore", 0)
    sections = [f"<h2>STAT Next Triage</h2><p><strong>Risk Score:</strong> {_html(score)}<br><strong>Entities Analyzed:</strong> {_html(base.get('EntitiesCount', 0))}</p>"]

    account_sections = []
    details = [x for x in aad.get("DetailedResults", []) if isinstance(x, dict)]
    risk_by_upn = {str(x.get("UserPrincipalName", "")).lower(): x for x in details}
    risk_by_id = {str(x.get("UserId", "")).lower(): x for x in details if x.get("UserId")}
    accounts = base.get("Accounts", [])
    for index, item in enumerate(accounts, start=1):
        r = _raw(item); a = _additional(r)
        upn = _first(a.get("UserPrincipalName"), a.get("userPrincipalName"), r.get("userPrincipalName"), r.get("upn"), item.get("UserPrincipalName"))
        uid = _first(r.get("aadUserId"), r.get("objectGuid"), a.get("AadUserId"), a.get("aadUserId"))
        risk = risk_by_upn.get(str(upn or "").lower()) or risk_by_id.get(str(uid or "").lower()) or {}
        rows = [
            ("UserPrincipalName", _portal_user(upn, uid)),
            ("City", _first(risk.get("City"), a.get("City"), a.get("city"), r.get("city"))),
            ("Country", _first(risk.get("Country"), a.get("Country"), a.get("country"), r.get("country"))),
            ("Department", _first(a.get("Department"), a.get("department"), r.get("department"), risk.get("Department"))),
            ("JobTitle", _first(a.get("JobTitle"), a.get("jobTitle"), r.get("jobTitle"), risk.get("JobTitle"))),
            ("Office", _first(a.get("OfficeLocation"), a.get("officeLocation"), r.get("officeLocation"), risk.get("Office"))),
            ("AADRoles", risk.get("AADRoles")),
            ("ManagerUPN", _mailto(risk.get("ManagerUPN"))),
            ("MfaRegistered", risk.get("MfaRegistered")),
            ("SSPREnabled", risk.get("SSPREnabled")),
            ("SSPRRegistered", risk.get("SSPRRegistered")),
            ("RiskLevel", risk.get("UserRiskLevel")),
            ("FailedMFA", risk.get("UserFailedMFACount")),
            ("MFAFraud", risk.get("UserMFAFraudCount")),
        ]
        label = "Account" if len(accounts) == 1 else f"Account {index}"
        account_sections.append(f"<h4>{label}</h4>" + _vertical_table(rows))
    if account_sections:
        sections.append("<h3>Account Info</h3>" + "".join(account_sections))

    ips = []
    for item in base.get("IPs", []):
        r = _raw(item); ips.append([item.get("Address") or r.get("address"), r.get("location") or r.get("countryCode"), r.get("friendlyName")])
    if ips:
        sections.append("<h3>IP Info</h3>" + _html_table(["IP", "Location", "Name"], ips))

    hosts = []
    for item in base.get("Hosts", []):
        r = _raw(item); hosts.append([item.get("Hostname"), item.get("DnsDomain"), item.get("FQDN"), r.get("mdatpDeviceId") or r.get("MdatpDeviceId"), r.get("lastIpAddress") or r.get("LastIpAddress"), r.get("lastExternalIpAddress") or r.get("LastExternalIpAddress")])
    if hosts:
        sections.append("<h3>Host Info</h3>" + _html_table(["Host", "Domain", "FQDN", "MDE Device ID", "Last IP", "External IP"], hosts))

    hashes = []
    for item in base.get("FileHashes", []):
        r = _raw(item); hashes.append([r.get("algorithm") or r.get("Algorithm"), r.get("value") or r.get("Value") or r.get("hashValue")])
    if hashes:
        sections.append("<h3>File Hash Info</h3>" + _html_table(["Algorithm", "Hash"], hashes))

    files = []
    for item in base.get("Files", []):
        r = _raw(item); files.append([r.get("fileName") or r.get("FileName") or r.get("name"), r.get("directory") or r.get("Directory") or r.get("path") or r.get("Path")])
    if files:
        sections.append("<h3>File Info</h3>" + _html_table(["File", "Path"], files))

    module_rows = [
        ["AAD / Identity Risk", f"Highest risk: {aad.get('HighestRiskLevel', 'unknown')}; failed MFA: {aad.get('FailedMFATotalCount', 0)}; fraud: {aad.get('MFAFraudTotalCount', 0)}", _module_context(aad, ["DetailedResults", "EnrichmentWarnings"])],
        ["Related Alerts", related.get("RelatedAlertsCount", 0), _module_context(related, ["RelatedAlerts", "Alerts", "DetailedResults"])],
        ["Threat Intelligence", ti.get("MatchedTIItemCount", 0), _module_context(ti, ["MatchedItems", "Matches", "DetailedResults"])],
        ["MDE", mde.get("AnalyzedEntities", mde.get("MachineCount", 0)), _module_context(mde, ["Machines", "DetailedResults", "Findings"])],
        ["UEBA", ueba.get("AnomalyCount", 0), _module_context(ueba, ["Anomalies", "DetailedResults", "Findings"])],
        ["File Insights", file_insights.get("HashesLinkedToThreatCount", 0), _module_context(file_insights, ["DetailedResults", "Findings", "Hashes"] )],
        ["Defender for Cloud Apps", mcas.get("AnalyzedEntities", mcas.get("MatchedCount", 0)), _module_context(mcas, ["DetailedResults", "Findings", "Matches"])],
    ]
    sections.append("<h3>Enrichment Summary</h3>" + _html_table(["Module", "Result", "Context"], module_rows))
    sections.append("<p><em>Generated by STAT Next using the Microsoft Sentinel incident payload and configured enrichment modules.</em></p>")
    return {"ModuleName": "STATComment", "Message": "".join(sections), "RiskScore": score}
