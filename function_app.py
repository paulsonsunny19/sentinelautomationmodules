import json
import logging
import uuid
import azure.functions as func
from modules.base import normalize
from modules.scoring import calculate
from modules.comment import build_comment
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
from modules.ip_baseline import IPBaselineRequest, query_ip_baseline
from modules.oof import OOFRequest, query_oof
from modules.run_playbook import RunPlaybookRequest, run_playbook

# HTTP authorization is enforced by App Service Authentication (Easy Auth).
# Anonymous here means the Functions runtime does not additionally require a
# function key after Easy Auth has validated the caller's Entra token.
app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)
def response(payload,status=200): return func.HttpResponse(json.dumps(payload,default=str),status_code=status,mimetype='application/json')
def body_json(req,cid):
    try:return req.get_json(),None
    except ValueError:return None,response({'error':'invalid_json','correlationId':cid},400)
def execute(req,name,required,handler):
    cid=str(uuid.uuid4()); body,error=body_json(req,cid)
    if error:return error
    missing=[x for x in required if body.get(x) is None]
    if missing:return response({'error':'missing_parameters','missing':missing,'correlationId':cid},400)
    try:return response({**handler(body),'correlationId':cid})
    except ValueError as exc:return response({'error':'invalid_parameters','message':str(exc),'correlationId':cid},400)
    except Exception:
        logging.exception('%s failed correlationId=%s',name,cid); return response({'error':name+'_failure','correlationId':cid},502)

def _trigger_entities(body):
    trigger=body.get('Body') if isinstance(body.get('Body'),dict) else (body.get('body') if isinstance(body.get('body'),dict) else {})
    obj=trigger.get('object') if isinstance(trigger.get('object'),dict) else {}
    props=obj.get('properties') if isinstance(obj.get('properties'),dict) else {}
    entities=props.get('relatedEntities')
    return entities if isinstance(entities,list) else (body.get('entities') if isinstance(body.get('entities'),list) else [])

def _incident_id(body):
    for key in ('incidentArmId','IncidentARMId','incidentARMId'):
        value=body.get(key)
        if value:return value
    trigger=body.get('Body') if isinstance(body.get('Body'),dict) else (body.get('body') if isinstance(body.get('body'),dict) else {})
    obj=trigger.get('object') if isinstance(trigger.get('object'),dict) else (body.get('object') if isinstance(body.get('object'),dict) else {})
    return obj.get('id') or trigger.get('incidentArmId') or trigger.get('IncidentARMId')

def _build_base(body):
    incident_id=_incident_id(body)
    if not incident_id:
        raise ValueError('incidentArmId is required for stat_base; send the full Microsoft Sentinel incident ARM resource ID')
    return normalize(_trigger_entities(body),incident_id,body['workspaceId'],body.get('tenantId'),body.get('tenantDisplayName'))

def _run_playbook_request(body):
    base=body.get('base') if isinstance(body.get('base'),dict) else {}
    return RunPlaybookRequest(body['logicAppResourceId'],body['tenantId'],base.get('IncidentARMId') or base.get('incidentArmId') or '')

@app.route(route='health',methods=['GET'])
def health(req):return response({'service':'STAT Next','status':'healthy','modules':['BaseModule','AADRisksModule','RelatedAlerts','TIModule','IPNetworkBaselineModule','WatchlistModule','KQLModule','MDEModule','UEBAModule','FileModule','MCASModule','OOFModule','RunPlaybook','ScoringModule','STATComment'],'correlationId':str(uuid.uuid4())})
@app.route(route='incident_context',methods=['POST'])
def incident_context(req):return execute(req,'sentinel_api',('subscriptionId','resourceGroup','workspaceName','incidentId'),lambda b:{'module':'sentinel.incident_context',**safe_incident_context(b['subscriptionId'],b['resourceGroup'],b['workspaceName'],b['incidentId'])})
@app.route(route='stat_base',methods=['POST'])
def stat_base(req):return execute(req,'stat_base',('workspaceId',),_build_base)
@app.route(route='stat_aad_risks',methods=['POST'])
def stat_aad_risks(req):return execute(req,'stat_aad_risks',('workspaceId','base'),lambda b:query_aad_risks(AADRisksRequest(b['workspaceId'],b['base'],int(b.get('lookbackDays',14)),bool(b.get('mfaFailureLookup',True)),bool(b.get('mfaFraudLookup',True)))))
@app.route(route='stat_related_alerts',methods=['POST'])
def stat_related_alerts(req):return execute(req,'stat_related_alerts',('workspaceId','base'),lambda b:query_related_alerts(RelatedAlertsRequest(b['workspaceId'],b['base'],int(b.get('lookbackDays',14)),b.get('alertKqlFilter',''),bool(b.get('checkAccounts',True)),bool(b.get('checkHosts',True)),bool(b.get('checkIPs',True)))))
@app.route(route='stat_threat_intel',methods=['POST'])
def stat_threat_intel(req):return execute(req,'stat_threat_intel',('workspaceId','base'),lambda b:query_threat_intel(ThreatIntelRequest(b['workspaceId'],b['base'],int(b.get('lookbackDays',14)),bool(b.get('checkIPs',True)),bool(b.get('checkDomains',True)),bool(b.get('checkURLs',True)),bool(b.get('checkFileHashes',True)))))
@app.route(route='stat_ip_baseline',methods=['POST'])
def stat_ip_baseline(req):return execute(req,'stat_ip_baseline',('workspaceId','base'),lambda b:query_ip_baseline(IPBaselineRequest(b['workspaceId'],b['base'],int(b.get('lookbackDays',30)))))
@app.route(route='stat_watchlist',methods=['POST'])
def stat_watchlist(req):return execute(req,'stat_watchlist',('workspaceId','base','watchlistAlias','watchlistKey','watchlistKeyDataType'),lambda b:query_watchlist(WatchlistRequest(b['workspaceId'],b['base'],b['watchlistAlias'],b['watchlistKey'],b['watchlistKeyDataType'])))
@app.route(route='stat_kql',methods=['POST'])
def stat_kql(req):return execute(req,'stat_kql',('workspaceId','base','query'),lambda b:run_kql(KQLRequest(b['workspaceId'],b['base'],b['query'],int(b.get('lookbackDays',14)),b.get('queryDescription'))))
@app.route(route='stat_mde',methods=['POST'])
def stat_mde(req):return execute(req,'stat_mde',('base',),lambda b:query_mde(MDERequest(b['base'],int(b.get('lookbackDays',14)))))
@app.route(route='stat_ueba',methods=['POST'])
def stat_ueba(req):return execute(req,'stat_ueba',('workspaceId','base'),lambda b:query_ueba(UEBARequest(b['workspaceId'],b['base'],int(b.get('lookbackDays',14)),int(b.get('minimumInvestigationPriority',1)))))
@app.route(route='stat_file',methods=['POST'])
def stat_file(req):return execute(req,'stat_file',('base',),lambda b:query_file_insights(FileInsightsRequest(b['base'])))
@app.route(route='stat_mcas',methods=['POST'])
def stat_mcas(req):return execute(req,'stat_mcas',('base',),lambda b:query_mcas(MCASRequest(b['base'],int(b.get('scoreThreshold',0)),b.get('portalUrl'))))
@app.route(route='stat_oof',methods=['POST'])
def stat_oof(req):return execute(req,'stat_oof',('base',),lambda b:query_oof(OOFRequest(b['base'])))
@app.route(route='stat_run_playbook',methods=['POST'])
def stat_run_playbook(req):return execute(req,'stat_run_playbook',('base','logicAppResourceId','tenantId'),lambda b:run_playbook(_run_playbook_request(b)))
@app.route(route='stat_scoring',methods=['POST'])
def stat_scoring(req):return execute(req,'stat_scoring',('inputs',),lambda b:calculate(b['inputs']) if isinstance(b['inputs'],list) else (_ for _ in ()).throw(ValueError('inputs must be an array')))
@app.route(route='stat_comment',methods=['POST'])
def stat_comment(req):return execute(req,'stat_comment',('base','scoring'),lambda b:build_comment(b['base'],b['scoring'],b.get('aad'),b.get('related'),b.get('ti'),b.get('ipBaseline'),b.get('mde'),b.get('ueba'),b.get('file'),b.get('mcas'),b.get('oof')))
