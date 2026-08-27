import json
import logging
import uuid
import azure.functions as func

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)


def response(payload: dict, status: int = 200) -> func.HttpResponse:
    return func.HttpResponse(
        json.dumps(payload, default=str),
        status_code=status,
        mimetype="application/json",
    )


@app.route(route="health", methods=["GET"])
def health(req: func.HttpRequest) -> func.HttpResponse:
    correlation_id = str(uuid.uuid4())
    return response({
        "service": "STAT Next",
        "status": "healthy",
        "correlationId": correlation_id,
    })


@app.route(route="v1/sentinel/related-alerts", methods=["POST"])
def related_alerts(req: func.HttpRequest) -> func.HttpResponse:
    correlation_id = str(uuid.uuid4())
    try:
        body = req.get_json()
    except ValueError:
        return response({"error": "invalid_json", "correlationId": correlation_id}, 400)

    required = ("subscriptionId", "resourceGroup", "workspaceName")
    missing = [name for name in required if not body.get(name)]
    if missing:
        return response({
            "error": "missing_parameters",
            "missing": missing,
            "correlationId": correlation_id,
        }, 400)

    # Query execution is implemented in modules/related_alerts.py. The API intentionally
    # accepts structured inputs rather than arbitrary KQL from callers.
    logging.info("STAT Next related-alerts request correlationId=%s", correlation_id)
    return response({
        "status": "module_scaffold",
        "module": "sentinel.related_alerts",
        "correlationId": correlation_id,
        "message": "API contract established; query implementation follows in the module layer."
    }, 501)
