from __future__ import annotations

import re
from typing import Any

from .comment import build_comment as _build_comment


_IP_SUMMARY_ROW = re.compile(r'<tr><td>IP Enrichment</td>.*?</tr>', re.DOTALL)


def build_comment(
    base: dict[str, Any],
    scoring: dict[str, Any],
    aad=None,
    related=None,
    ti=None,
    ip_baseline=None,
    mde=None,
    ueba=None,
    file_insights=None,
    mcas=None,
    oof=None,
):
    """Build the native Sentinel incident comment without IP GeoData enrichment.

    IP GeoData remains available through the standalone stat_ip_enrichment API,
    but the native incident workflow intentionally does not surface its results,
    warnings, or partial-enrichment state.
    """
    result = _build_comment(
        base,
        scoring,
        aad,
        related,
        ti,
        ip_baseline,
        mde,
        ueba,
        file_insights,
        mcas,
        oof,
        {},
    )
    result['Message'] = _IP_SUMMARY_ROW.sub('', result.get('Message', ''))
    return result
