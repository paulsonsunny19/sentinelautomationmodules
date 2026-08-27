import json
import logging
import uuid
import azure.functions as func
from modules.base import normalize
from modules.scoring import calculate
from modules.related_alerts import RelatedAlertsRequest, query_related_alerts
from modules.sentinel import safe_incident_context
from modules.threat_intel import ThreatIntelRequest, query_threat_intel
from modules.watchlist import WatchlistRequest, query_watchlist
from modules.kql import KQLRequest, run_kql
from modules.aad_risks import AADRisksRequest, query_aad_risks
from modules.mde import MDERequest, query_mde
from modules.ueba import UEBARequest, query_ueba
from modules.file_insights import FileInsightsRequest, query_file_insights
from modules.mcas import MCASRequest, query_mcas

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

def response(payload: dict, status: int = 200) -> func.HttpResponse:
    return func.HttpResponse(json.dumps(payload, default=str), status_code=status, mimetype="application/json")

def body_json(req: func.HttpRequest, correlation_id: str):
    try: return req.get_json(), None
    except ValueError: return None, response({"error":"invalid_json","correlationId":correlation_id}, 400)

def execute(req, name, required, handler):
    cid=str(uuid.uuid4()); body,error=body_json(req,cid)
    if error:return error
    missing=[x for x in required if body.get(x) is None]
    if missing:return response({"error":"missing_parameters","missing":missing,"correlationId":cid},400)
    try:return response({**handler(body),"correlationId":cid})
    except ValueError as exc:return response({"error":"invalid_parameters","message":str(exc),"correlationId":cid},400)
    except Exception:
        logging.exception("%s failed correlationId=%s",name,cid)
        return response({"error":name+"_failure","correlationId":cid},502)

@app.route(route="health", methods=["GET"])
def health(req): return response({"service":"STAT Next","status":"healthy","modules":["BaseModule","AADRisksModule","RelatedAlerts","TIModule","WatchlistModule","KQLModule","MDEModule","UEBAModule","FileModule","MCASModule","ScoringModule"],"correlationId":str(uuid.uuid4())})

@app.route(route="incident_context", methods=["POST"])
def incident_context(req):
    def run(b): return {"module":"sentinel.incident_context",**safe_incident_context(b["subscriptionId"],b["resourceGroup"],b["workspaceName"],b["incidentId"])}
    return execute(req,"sentinel_api",("subscriptionId","resourceGroup","workspaceName","incidentId"),run)

@app.route(route="stat_base", methods=["POST"])
def stat_base(req): return execute(req,"stat_base",("entities","incidentArmId","workspaceId"),lambda b: normalize(b["entities"],b["incidentArmId"],b["workspaceId"],b.get("tenantId"),b.get("tenantDisplayName")))

@app.route(route="stat_aad_risks", methods=["POST"])
def stat_aad_risks(req): return execute(req,"stat_aad_risks",("workspaceId","base"),lambda b: query_aad_risks(AADRisksRequest(b["workspaceId"],b["base"],int(b.get("lookbackDays",14)),bool(b.get("mfaFailureLookup",True)),bool(b.get("mfaFraudLookup",True)))))

@app.route(route="stat_threat_intel", methods=["POST"])
def stat_threat_intel(req): return execute(req,"stat_threat_intel",("workspaceId","base"),lambda b: query_threat_intel(ThreatIntelRequest(b["workspaceId"],b["base"],int(b.get("lookbackDays",14)),bool(b.get("checkIPs",True)),bool(b.get("checkDomains",True)),bool(b.get("checkURLs",True)),bool(b.get("checkFileHashes",True)))))

@app.route(route="stat_watchlist", methods=["POST"])
def stat_watchlist(req): return execute(req,"stat_watchlist",("workspaceId","base","watchlistAlias","watchlistKey","watchlistKeyDataType"),lambda b: query_watchlist(WatchlistRequest(b["workspaceId"],b["base"],b["watchlistAlias"],b["watchlistKey"],b["watchlistKeyDataType"])))

@app.route(route="stat_kql", methods=["POST"])
def stat_kql(req): return execute(req,"stat_kql",("workspaceId","base","query"),lambda b: run_kql(KQLRequest(b["workspaceId"],b["base"],b["query"],int(b.get("lookbackDays",14)),b.get("queryDescription"))))

@app.route(route="stat_mde", methods=["POST"])
def stat_mde(req): return execute(req,"stat_mde",("base",),lambda b: query_mde(MDERequest(b["base"],int(b.get("lookbackDays",14)))))

@app.route(route="stat_ueba", methods=["POST"])
def stat_ueba(req): return execute(req,"stat_ueba",("workspaceId","base"),lambda b: query_ueba(UEBARequest(b["workspaceId"],b["base"],int(b.get("lookbackDays",14)),int(b.get("minimumInvestigationPriority",1)))))

@app.route(route="stat_file", methods=["POST"])
def stat_file(req): return execute(req,"stat_file",("base",),lambda b: query_file_insights(FileInsightsRequest(b["base"])))

@app.route(route="stat_mcas", methods=["POST"])
def stat_mcas(req): return execute(req,"stat_mcas",("base",),lambda b: query_mcas(MCASRequest(b["base"],int(b.get("scoreThreshold",0)),b.get("portalUrl"))))

@app.route(route="stat_scoring", methods=["POST"])
def stat_scoring(req): return execute(req,"stat_scoring",("inputs",),lambda b: calculate(b["inputs"]) if isinstance(b["inputs"],list) else (_ for _ in ()).throw(ValueError("inputs must be an array")))

@app.route(route="v1/sentinel/related-alerts", methods=["POST"])
def related_alerts(req):
    def run(b):
        rows=query_related_alerts(RelatedAlertsRequest(b["workspaceId"],b["entityValue"],b["entityColumn"],int(b.get("lookbackHours",24))))
        return {"ModuleName":"RelatedAlerts","AnalyzedEntities":1,"DetailedResults":rows,"Alerts":rows,"count":len(rows)}
    return execute(req,"related_alerts",("workspaceId","entityValue","entityColumn"),run)
