from __future__ import annotations

import math
from typing import Any

SEVERITY = {"high": 10, "medium": 5, "low": 3, "informational": 1, "none": 0, "unknown": 0}
MAX_SCORE_MULTIPLIER = 100.0


def _sev(value: Any) -> int:
    return SEVERITY.get(str(value or "unknown").lower(), 0)


def _item(score: float, source: str) -> dict[str, Any]:
    return {"Score": score, "ScoreSource": source}


def _multiplier(value: Any) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError('scoreMultiplier must be a number') from exc
    if not math.isfinite(number) or number < 0 or number > MAX_SCORE_MULTIPLIER:
        raise ValueError(f'scoreMultiplier must be finite and between 0 and {MAX_SCORE_MULTIPLIER:g}')
    return number


def _count(value: Any) -> int:
    try:
        number = int(value or 0)
    except (TypeError, ValueError, OverflowError):
        return 0
    return max(0, number)


def _nonnegative_number(value: Any) -> float:
    try:
        number = float(value or 0)
    except (TypeError, ValueError, OverflowError):
        return 0.0
    return number if math.isfinite(number) and number > 0 else 0.0


def score_module(module: dict[str, Any], multiplier: float = 1, score_per_item: bool = True, label: str | None = None) -> list[dict[str, Any]]:
    if not isinstance(module, dict):
        return []
    multiplier = _multiplier(multiplier)
    name = str(module.get("ModuleName") or label or "Custom")
    out: list[dict[str, Any]] = []
    if name == "AADRisksModule":
        risks = [_sev(x.get("UserRiskLevel")) for x in module.get("DetailedResults", []) if isinstance(x, dict)]
        vals = risks if score_per_item else ([max(risks)] if risks else [])
        out += [_item(v * multiplier, label or "AAD Risks") for v in vals if v]
    elif name in ("RelatedAlerts", "RelatedAlertsModule"):
        alerts = module.get("DetailedResults", module.get("Alerts", []))
        alerts = alerts if isinstance(alerts, list) else []
        vals = [_sev(x.get("AlertSeverity") or x.get("severity")) for x in alerts if isinstance(x, dict)]
        vals = vals if score_per_item else ([max(vals)] if vals else [])
        out += [_item(v * multiplier, label or "Related Alerts") for v in vals if v]
        # Upstream STAT adds 10 per unique MITRE tactic. RelatedAlerts emits AllTactics;
        # retain UniqueTactics compatibility for older callers.
        raw_tactics = module.get("AllTactics") or module.get("UniqueTactics") or []
        tactics = set(raw_tactics) if isinstance(raw_tactics, list) else set()
        if tactics:
            out.append(_item(len(tactics) * 10 * multiplier, label or "Related Alerts - MITRE tactics"))
    elif name in ("TIModule", "ThreatIntelligenceModule"):
        count = _count(module.get("MatchedTIItemCount", 0)); qty = count if score_per_item else int(count > 0)
        if qty: out.append(_item(10 * qty * multiplier, label or "Threat Intelligence"))
    elif name == "WatchlistModule":
        count = _count(module.get("WatchlistMatchCount", 0)); qty = count if score_per_item else int(count > 0)
        if qty: out.append(_item(10 * qty * multiplier, label or "Watchlist"))
    elif name == "FileModule":
        count = _count(module.get("HashesLinkedToThreatCount", 0))
        if count: out.append(_item(10 * count * multiplier, label or "File"))
    elif name in ("MCASModule", "MDCAModule"):
        count = _count(module.get("AboveThresholdCount", module.get("AboveThreholdCount", 0))); qty = count if score_per_item else int(count > 0)
        if qty: out.append(_item(10 * qty * multiplier, label or "Defender for Cloud Apps"))
    elif name == "KQLModule":
        count = _count(module.get("ItemCount", module.get("ResultsCount", 0))); qty = count if score_per_item else int(count > 0)
        if qty: out.append(_item(5 * qty * multiplier, label or "KQL"))
    elif name == "MDEModule":
        vals = [_sev(module.get(k)) for k in ("UsersHighestRiskScore", "HostsHighestRiskScore", "IPsHighestRiskScore")]
        value = sum(vals) if score_per_item else max(vals)
        if value: out.append(_item(value * multiplier, label or "Microsoft Defender for Endpoint"))
    elif name == "UEBAModule":
        priority = _nonnegative_number(module.get("InvestigationPriorityMax" if score_per_item else "AllEntityInvestigationPriorityMax", 0))
        ti = _count(module.get("ThreatIntelMatchCount", 0))
        tactics = _count(module.get("AnomalyTacticsCount", 0))
        value = (priority + (10 if ti else 0) + tactics * 10) * multiplier
        if value: out.append(_item(value, label or "UEBA"))
    else:
        scoring_data = module.get("ScoringData", [])
        scoring_data = scoring_data if isinstance(scoring_data, list) else []
        for entry in scoring_data:
            if not isinstance(entry, dict):
                continue
            score = entry.get("Score")
            if isinstance(score, (int, float)) and not isinstance(score, bool):
                numeric = float(score)
                # Custom enrichment can add context/risk, but it may not reduce
                # incident severity or poison totals with NaN/Infinity.
                if math.isfinite(numeric) and numeric >= 0:
                    out.append(_item(numeric * multiplier, str(entry.get("ScoreLabel") or label or "Custom")))
    return out


def calculate(inputs: list[dict[str, Any]]) -> dict[str, Any]:
    if not isinstance(inputs, list):
        raise ValueError('inputs must be an array')
    details: list[dict[str, Any]] = []
    for item in inputs:
        if not isinstance(item, dict):
            continue
        module = item.get("module", {})
        if not isinstance(module, dict):
            # Logic Apps may pass an empty/null body when an enrichment action
            # was allowed to fail. Scoring must preserve the remaining modules.
            continue
        multiplier = _multiplier(item.get("scoreMultiplier", 1))
        details.extend(score_module(module, multiplier, bool(item.get("scorePerItem", True)), item.get("scoreLabel")))
    total = sum(float(x["Score"]) for x in details)
    if not math.isfinite(total):
        raise ValueError('scoring total must be finite')
    return {"ModuleName": "ScoringModule", "DetailedResults": details, "TotalScore": total}
