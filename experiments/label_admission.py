"""Evidence admission v1. Audits records; does not infer truth from detector output."""
import re
from datetime import datetime
from urllib.parse import urlsplit

POLICY_ID='analyst-case-admission-v1'
BEHAVIORS={'credential_exfiltration','backdoor_command_channel','ransomware_encryption',
           'destructive_wiper','unauthorized_payload_loader'}


def located(evidence):
    try:
        url=urlsplit(evidence.get('source_url',''))
        locator=evidence.get('locator')
        return (url.scheme=='https' and bool(url.hostname) and not re.search(r'\s',url.netloc)
                and url.username is None and isinstance(locator,str) and bool(locator.strip()))
    except (ValueError,TypeError):
        return False


def assess(row):
    exclusions=[]
    if not re.fullmatch('[0-9a-f]{64}',str(row.get('sha256',''))):
        exclusions.append('invalid_sha256')
    if any(row.get(key) is not False for key in ('dual_use','family_conflict','source_disputed')):
        exclusions.append('ambiguity_not_cleared')
    evidence=[e for e in row.get('evidence',[]) if e.get('sha256')==row.get('sha256')
              and e.get('primary') is True and e.get('independent_of_aegisav') is True
              and e.get('kind')=='technical_analysis' and e.get('behavior') in BEHAVIORS
              and located(e)]
    if not evidence:
        exclusions.append('precise_independent_technical_evidence_missing')
    raw=row.get('raw')
    if raw and (raw.get('sha256')!=row.get('sha256') or raw.get('integrity_verified') is not True
                or raw.get('strict_pe_valid') is not True):
        exclusions.append('raw_integrity_or_pe_invalid')
    review=row.get('review',{})
    try:
        dated=datetime.fromisoformat(review.get('reviewed_at','')).utcoffset() is not None
    except (ValueError,TypeError):
        dated=False
    reviewer=review.get('reviewer')
    accepted=(review.get('status')=='accepted' and isinstance(reviewer,str) and bool(reviewer.strip())
              and dated and review.get('method') in {'automated','human'})
    grade='unknown' if exclusions else 'high-confidence' if raw and accepted else 'probable'
    formal=[]
    if grade!='high-confidence': formal.append('high_confidence_raw_required')
    if review.get('method')!='human' or not accepted: formal.append('human_review_pending')
    if row.get('dataset_role')!='final_candidate' or row.get('detector_results_observed') is not False:
        formal.append('already_observed_or_nonfinal_role')
    for key in ('split_frozen_before_scan','training_overlap_cleared','near_overlap_cleared','temporal_eligibility_verified'):
        if row.get(key) is not True: formal.append(key)
    return dict(policy_id=POLICY_ID,grade=grade,exclusions=exclusions,
                exploratory_eligible=grade=='high-confidence',formal_eligible=not formal,
                formal_exclusions=formal,review_method=review.get('method'),
                caveat='Auditable analyst evidence confidence, not absolute truth; automated review is not human review.')
