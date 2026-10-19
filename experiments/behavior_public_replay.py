"""Replay a pinned MIT-licensed OTRF log. Download logs only, never programs."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import threading
import time
import urllib.request
import zipfile

from aegisav.scan_process import ProcessScanner

REVISION='d9d40ef123d2c87d5d3df28c96bcab4f0faccc87'
PATH='datasets/atomic/windows/discovery/host/cmd_discover_iexplorer_version_registry.zip'
SOURCE=f'https://github.com/OTRF/Security-Datasets/blob/{REVISION}/{PATH}'


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output',type=Path)
    args=parser.parse_args()
    root=Path(__file__).resolve().parents[1]
    output=args.output.resolve()
    if not output.is_relative_to(root/'artifacts') or output.exists():
        parser.error('Use a fresh private directory under artifacts')
    url=f'https://raw.githubusercontent.com/OTRF/Security-Datasets/{REVISION}/{PATH}'
    with urllib.request.urlopen(url,timeout=30) as response:
        raw=response.read(128*1024+1)
    if len(raw)>128*1024: raise ValueError('Public log archive limit exceeded')
    archive=zipfile.ZipFile(io.BytesIO(raw))
    members=archive.infolist()
    if len(members)!=1 or not members[0].filename.endswith('.json') or members[0].file_size>1024**2:
        raise ValueError('Expected one bounded JSON log member; no filesystem extraction')
    with archive.open(members[0]) as stream: original=stream.read(1024**2+1)
    if len(original)>1024**2: raise ValueError('Expanded log limit exceeded')
    rows=[json.loads(line) for line in original.decode('utf-8').splitlines() if line.strip()]
    records=[]
    excluded={'Message','EventID','SourceName','Hostname','TimeCreated','@timestamp','ProviderGuid','Channel','Task','Level','Keywords'}
    for row in rows:
        if row.get('SourceName')!='Microsoft-Windows-Sysmon': continue
        records.append(dict(event_id=row['EventID'],provider=row['SourceName'],computer=row.get('Hostname'),
            timestamp=row.get('TimeCreated'),record_id=str(row['EventRecordID']) if row.get('EventRecordID') else None,
            fields={key:str(value) for key,value in row.items() if key not in excluded}))
    normalized=(json.dumps({'events':records},ensure_ascii=False)+'\n').encode()
    runner=ProcessScanner(command=[__import__('sys').executable,'-m','aegisav.behavior_worker'],memory_bytes=256*1024**2)
    start=time.monotonic(); report=runner.scan(normalized,threading.Event(),start+20)
    output.mkdir(parents=True)
    (output/'normalized.json').write_bytes(normalized)
    (output/'report.json').write_bytes((json.dumps(report,ensure_ascii=False,indent=2)+'\n').encode())
    summary=dict(source=SOURCE,revision=REVISION,license='MIT',
        license_source=f'https://github.com/OTRF/Security-Datasets/blob/{REVISION}/LICENSE',
        archive_sha256=hashlib.sha256(raw).hexdigest(),member_sha256=hashlib.sha256(original).hexdigest(),
        normalized_sha256=hashlib.sha256(normalized).hexdigest(),raw_events=len(rows),sysmon_events=len(records),
        excluded_non_sysmon_events=len(rows)-len(records),
        status=report['status'],coverage=report['coverage'],parse_errors=report['parse_errors'],
        rules=[dict(rule_id=r['rule_id'],status=r['status']) for r in report['rules']],
        processes=len(report['processes']),wall_ms=(time.monotonic()-start)*1000,
        memory_limit_bytes=runner.memory_bytes,worker_cleaned=runner.active_pid is None and runner.healthy,
        normalization='SourceName,Hostname,TimeCreated -> metadata; all remaining fields retained except redundant rendered Message/system metadata',
        timestamp_note='Source TimeCreated retained with UtcTime in fields; time discrepancies are not resolved as causal evidence',
        program_execution=False,malware_accuracy_evaluation=False)
    (output/'summary.json').write_bytes((json.dumps(summary,indent=2)+'\n').encode())
    print(json.dumps({k:summary[k] for k in ('raw_events','sysmon_events','status','processes','wall_ms','worker_cleaned')}))


if __name__=='__main__': main()
