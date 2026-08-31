from __future__ import annotations
from dataclasses import dataclass
from typing import Any
import json, urllib.request
from azure.identity import DefaultAzureCredential

@dataclass(frozen=True)
class FileInsightsRequest:
    base: dict[str, Any]


def _hashes(base:dict[str,Any])->list[tuple[str,str]]:
    out=[]
    for x in base.get('FileHashes',[]):
        r=x.get('RawEntity',x); value=x.get('Value') or r.get('value') or r.get('hashValue'); alg=str(x.get('Algorithm') or r.get('algorithm') or '').upper()
        if value: out.append((alg,str(value)))
    return list(dict.fromkeys(out))


def _advanced_query(credential:DefaultAzureCredential,query:str)->list[dict[str,Any]]:
    token=credential.get_token('https://api.securitycenter.microsoft.com/.default').token
    request=urllib.request.Request('https://api.securitycenter.microsoft.com/api/advancedqueries/run',data=json.dumps({'Query':query}).encode(),method='POST',headers={'Authorization':f'Bearer {token}','Content-Type':'application/json'})
    with urllib.request.urlopen(request,timeout=30) as response:return json.loads(response.read().decode()).get('Results',[])


def query_file_insights(req:FileInsightsRequest)->dict[str,Any]:
    hashes=_hashes(req.base); credential=DefaultAzureCredential(exclude_interactive_browser_credential=True); details=[]
    for alg,value in hashes:
        escaped=value.replace("'","''")
        # FileProfile accepts SHA1/SHA256. Email attachment lookup also gives context for file entities.
        query=f'''let H="{escaped}";
let Attach=EmailAttachmentInfo | where SHA1 == H or SHA256 == H | summarize EmailAttachmentCount=count(), EmailAttachmentFileSize=max(FileSize), EmailAttachmentFirstSeen=min(Timestamp), EmailAttachmentLastSeen=max(Timestamp), FileName=take_any(FileName) by SHA1, SHA256;
let Profile=datatable(SHA1:string,SHA256:string)[];
union Attach | project FileName, EmailAttachmentCount, EmailAttachmentFileSize, EmailAttachmentFirstSeen, EmailAttachmentLastSeen, SHA1, SHA256'''
        rows=[]
        try: rows=_advanced_query(credential,query)
        except Exception: pass
        profile=[]
        if alg in ('SHA1','SHA256') or len(value) in (40,64):
            column='SHA1' if alg=='SHA1' or len(value)==40 else 'SHA256'
            try: profile=_advanced_query(credential,f'''FileProfile({column}="{escaped}", 1000) | take 1 | project GlobalFirstSeen,GlobalLastSeen,GlobalPrevalence,IsCertificateValid,MD5,Publisher,SHA1,SHA256,SignatureState,ThreatName''')
            except Exception: pass
        p=profile[0] if profile else {}; a=rows[0] if rows else {}
        details.append({'EmailAttachmentCount':int(a.get('EmailAttachmentCount') or 0),'EmailAttachmentFileSize':a.get('EmailAttachmentFileSize') or '','EmailAttachmentFirstSeen':a.get('EmailAttachmentFirstSeen') or '','EmailAttachmentLastSeen':a.get('EmailAttachmentLastSeen') or '','FileName':a.get('FileName') or '','GlobalFirstSeen':p.get('GlobalFirstSeen') or '','GlobalLastSeen':p.get('GlobalLastSeen') or '','GlobalPrevalence':p.get('GlobalPrevalence'),'IsCertificateValid':p.get('IsCertificateValid'),'MD5':p.get('MD5') or (value if alg=='MD5' else ''),'Publisher':p.get('Publisher') or '','SHA1':p.get('SHA1') or (value if alg=='SHA1' else ''),'SHA256':p.get('SHA256') or (value if alg=='SHA256' else ''),'SignatureState':p.get('SignatureState') or '','ThreatName':p.get('ThreatName') or ''})
    prevalences=[int(x['GlobalPrevalence']) for x in details if x.get('GlobalPrevalence') is not None]
    threats=sorted(set(str(x['ThreatName']) for x in details if x.get('ThreatName')))
    return {'AnalyzedEntities':len(details),'EntitiesAttachmentCount':sum(int(x['EmailAttachmentCount']) for x in details),'HashedInvalidSignatureCount':sum(1 for x in details if x.get('SignatureState') and x.get('SignatureState')!='SignedValid'),'HashesLinkedToThreatCount':sum(1 for x in details if x.get('ThreatName')),'HashesNotMicrosoftSignedCount':sum(1 for x in details if x.get('Publisher') and 'microsoft' not in str(x.get('Publisher')).lower()),'HashesThreatList':threats,'MaximumGlobalPrevalence':max(prevalences) if prevalences else 0,'MinimumGlobalPrevalence':min(prevalences) if prevalences else 0,'ModuleName':'FileModule','DetailedResults':details}
