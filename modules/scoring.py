from __future__ import annotations
from typing import Any

SEVERITY = {"high": 10, "medium": 5, "low": 3, "informational": 1, "none": 0, "unknown": 0}


def _sev(value: Any) -> int:
    return SEVERITY.get(str(value or "unknown").lower(), 0)


def _item(score: float, source: str) -> dict[str, Any]:
    return {"Score": score, "ScoreSource": source}


def score_module(module: dict[str, Any], multiplier: float = 1, score_per_item: bool = True, label: str | None = None) -> list[dict[str, Any]]:
    name = str(module.get("ModuleName") or label or "Custom")
    out: list[dict[str, Any]] = []
    if name == "AADRisksModule":
        risks = [_sev(x.get("UserRiskLevel")) for x in module.get("DetailedResults", [])]
        vals = risks if score_per_item else ([max(risks)] if risks else [])
        out += [_item(v * multiplier, label or "AAD Risks") for v in vals if v]
    elif name in ("RelatedAlerts", "RelatedAlertsModule"):
        alerts = module.get("DetailedResults", module.get("Alerts", []))
        vals = [_sev(x.get("AlertSeverity") or x.get("severity")) for x in alerts]
        vals = vals if score_per_item else ([max(vals)] if vals else [])
        out += [_item(v * multiplier, label or "Related Alerts") for v in vals if v]
        tactics = set(module.get("UniqueTactics", []))
        out += [_item(len(tactics) * 10 * multiplier, label or "Related Alerts - MITRE tactics")] if tactics else []
    elif name in ("TIModule", "ThreatIntelligenceModule"):
        count = int(module.get("MatchedTIItemCount", 0))
        qty = count if score_per_item else int(count > 0)
        if qty: out.append(_item(10 * qty * multiplier, label or "Threat Intelligence"))
    elif name == "WatchlistModule":
        count = int(module.get("WatchlistMatchCount", 0)); qty = count if score_per_item else int(count > 0)
        if qty: out.append(_item(10 * qty * multiplier, label or "Watchlist"))
    elif name == "FileModule":
        count = int(module.get("HashesLinkedToThreatCount", 0))
        if count: out.append(_item(10 * count * multiplier, label or "File"))
    elif name in ("MCASModule", "MDCAModule"):
        count = int(module.get("AboveThresholdCount", 0)); qty = count if score_per_item else int(count > 0)
        if qty: out.append(_item(10 * qty * multiplier, label or "Defender for Cloud Apps"))
    elif name == "KQLModule":
        count = int(module.get("ItemCount", 0)); qty = count if score_per_item else int(count > 0)
        if qty: out.append(_item(5 * qty * multiplier, label or "KQL"))
    elif name == "MDEModule":
        vals = [_sev(module.get(k)) for k in ("UsersHighestRiskScore", "HostsHighestRiskScore", "IPsHighestRiskScore")]
        value = sum(vals) if score_per_item else max(vals)
        if value: out.append(_item(value * multiplier, label or "Microsoft Defender for Endpoint"))
    elif name == "UEBAModule":
        priority = float(module.get("InvestigationPriorityMax" if score_per_item else "AllEntityInvestigationPriorityMax", 0) or 0)
        ti = int(module.get("ThreatIntelMatchCount", 0) or 0)
        tactics = int(module.get("AnomalyTacticsCount", 0) or 0)
        value = (priority + (10 if ti else 0) + tactics * 10) * multiplier
        if value: out.append(_item(value, label or "UEBA"))
    else:
        for entry in module.get("ScoringData", []):
            score = entry.get("Score")
            if isinstance(score, int) and not isinstance(score, bool):
                out.append(_item(score * multiplier, str(entry.get("ScoreLabel") or label or "Custom")))
    return out


def calculate(inputs: list[dict[str, Any]]) -> dict[str, Any]:
    details: list[dict[str, Any]] = []
    for item in inputs:
        details.extend(score_module(item.get("module", {}), float(item.get("scoreMultiplier", 1)), bool(item.get("scorePerItem", True)), item.get("scoreLabel")))
    return {"ModuleName": "ScoringModule", "DetailedResults": details, "TotalScore": sum(x["Score"] for x in details)}
