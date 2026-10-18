"""Outcome-blind, bounded availability-first research intake; no truth inference."""
from collections import Counter,defaultdict
import hashlib
import re
from urllib.parse import urlsplit

POLICY_ID='availability-first-family-balanced-v1'


def select_available(rows,excluded,limit=96,per_family=8):
    if not 1<=limit<=120 or not 1<=per_family<=8:raise ValueError('sampling_budget')
    groups=defaultdict(list);reasons=Counter();seen=set()
    for row in rows:
        sha=row.get('sha256_hash')
        size=row.get('file_size')
        if not isinstance(sha,str) or not re.fullmatch('[0-9a-f]{64}',sha):reason='identity'
        elif sha in seen:reason='duplicate'
        elif sha in excluded:reason='prior_identity'
        elif row.get('file_type') not in {'exe','dll'}:reason='type'
        elif type(size) is not int or not 0<size<=16*1024**2:reason='size'
        else:reason=None
        if reason:reasons[reason]+=1;continue
        seen.add(sha)
        family=row.get('signature') or 'unknown'
        if not isinstance(family,str) or len(family)>100:family='unknown'
        groups[family].append(dict(sha256=sha,file_size=size,family_proxy=family,
            file_type=row['file_type'],first_seen_provider=row.get('first_seen'),
            reporter=row.get('reporter'),imphash=row.get('imphash'),tlsh=row.get('tlsh'),
            source_url='https://bazaar.abuse.ch/sample/'+sha+'/',
            label='proxy_malicious_unreviewed',detector_results_observed=False,formal_eligible=False))
    for group in groups.values():group.sort(key=lambda r:hashlib.sha256((POLICY_ID+r['sha256']).encode()).hexdigest())
    selected=[];families=sorted(groups)
    for index in range(per_family):
        for family in families:
            if index<len(groups[family]) and len(selected)<limit:selected.append(groups[family][index])
    return dict(policy_id=POLICY_ID,selected=selected,exclusions=dict(reasons),
        eligible=sum(map(len,groups.values())),eligible_family_proxies=len(groups),
        selected_family_proxies=len({r['family_proxy'] for r in selected}),
        selection_uses_detector_results=False)


def select_reviewed_available(rows,primary,excluded,limit=96,per_family=8):
    """Role review authorizes intake, not a truth label or human admission."""
    reviewed={}
    for item in primary:
        if item.get('payload_role_reviewed') is not True:continue
        sha=item.get('sha256','');url=urlsplit(item.get('source_url',''))
        if (not re.fullmatch('[0-9a-f]{64}',sha) or sha in reviewed
                or url.scheme!='https' or not url.hostname or url.username is not None
                or not re.fullmatch('[0-9a-f]{64}',item.get('source_text_sha256',''))
                or not isinstance(item.get('locator'),str) or not item['locator'].strip()):
            raise ValueError('primary_evidence')
        reviewed[sha]={k:item.get(k) for k in ('source_url','source_text_sha256','locator','reported_family')}
    allowed=[r for r in rows if r.get('sha256_hash') in reviewed]
    result=select_available(allowed,excluded,limit,per_family)
    result['policy_id']='availability-first-reviewed-payload-v2'
    result['exclusions']['role_not_reviewed']=len(rows)-len(allowed)
    for row in result['selected']:row['technical_evidence']=reviewed[row['sha256']]
    return result
