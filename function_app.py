import json
import logging
import uuid
import azure.functions as func
from modules.related_alerts import RelatedAlertsRequest, query_related_alerts
from modules.sentinel import safe_incident_context

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)


def response(payload: dict, status: int = 200) -> func.HttpResponse:
    return func.HttpResponse(json.dumps(payload, default=str), status_code=status, mimetype="application/json")


def body_json(req: func.HttpRequest, correlation_id: str):
    try:
        return req.get_json(), None
    except ValueError:
        return None, response({"error":"invalid_json","correlationId":correlation_id}, 400)


@app.route(route="health", methods=["GET"])
def health(req: func.HttpRequest) -> func.HttpResponse:
    return response({"service":"STAT Next","status":"healthy","correlationId":str(uuid.uuid4())})


@app.route(route="v1/sentinel/incident-context", methods=["POST"])
def incident_context(req: func.HttpRequest) -> func.HttpResponse:
    correlation_id = str(uuid.uuid4())
    body, error = body_json(req, correlation_id)
    if error: return error
    required = ("subscriptionId","resourceGroup","workspaceName","incidentId")
    missing = [name for name in required if not body.get(name)]
    if missing: return response({"error":"missing_parameters","missing":missing,"correlationId":correlation_id}, 400)
    try:
        context = safe_incident_context(body["subscriptionId"], body["resourceGroup"], body["workspaceName"], body["incidentId"])
        return response({"module":"sentinel.incident_context","correlationId":correlation_id,**context})
    except RuntimeError as exc:
        logging.exception("Sentinel incident context failed correlationId=%s", correlation_id)
        return response({"error":"sentinel_api_failure","message":str(exc),"correlationId":correlation_id}, 502)


@app.route(route="v1/sentinel/related-alerts", methods=["POST"])
def related_alerts(req: func.HttpRequest) -> func.HttpResponse:
    correlation_id = str(uuid.uuid4())
    body, error = body_json(req, correlation_id)
    if error: return error
    required = ("workspaceId","entityValue","entityColumn")
    missing = [name for name in required if not body.get(name)]
    if missing: return response({"error":"missing_parameters","missing":missing,"correlationId":correlation_id}, 400)
    try:
        request = RelatedAlertsRequest(body["workspaceId"], body["entityValue"], body["entityColumn"], int(body.get("lookbackHours",24)))
        rows = query_related_alerts(request)
        return response({"module":"sentinel.related_alerts","count":len(rows),"alerts":rows,"correlationId":correlation_id})
    except ValueError as exc:
        return response({"error":"invalid_parameters","message":str(exc),"correlationId":correlation_id}, 400)
    except Exception:
        logging.exception("Related Alerts failed correlationId=%s", correlation_id)
        return response({"error":"related_alerts_failure","correlationId":correlation_id}, 502)
