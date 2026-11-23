"""Replay synthetic course logs with the existing CLI; never execute log commands."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


ROOT=Path(__file__).resolve().parents[1]
CERTUTIL='19b08b1c-861d-4e75-a1ef-ea0c1baf202b'
WHOAMI='bd8b828d-0dca-48e1-8a63-8a58ecf2644f'


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output',type=Path,help='New directory outside the source checkout')
    args=parser.parse_args()
    output=args.output.resolve()
    if output.is_relative_to(ROOT) or output.exists():
        parser.error('Use a new output directory outside the source checkout')

    # All fields below are invented descriptions, including reserved .invalid URLs.
    chain=json.loads((ROOT/'backend/tests/fixtures/sysmon_harmless.json').read_bytes())['events']
    certutil=copy.deepcopy(chain[1])
    certutil['fields']['OriginalFileName']='CertUtil.exe'
    whoami=copy.deepcopy(certutil)
    whoami.update(timestamp='2026-10-19T00:00:07Z',record_id='7')
    whoami['fields'].update(ProcessGuid='{course-whoami}',ProcessId='42',
        ParentProcessGuid=chain[0]['fields']['ProcessGuid'],
        Image=r'C:\Windows\System32\whoami.exe',OriginalFileName='whoami.exe',
        CommandLine='whoami /groups')
    benign=[copy.deepcopy(certutil),copy.deepcopy(whoami)]
    benign[0]['fields']['CommandLine']='certutil -hashfile C:\\Lab\\inert.txt SHA256'
    benign[1]['fields']['CommandLine']='whoami /user'
    missing=copy.deepcopy(certutil)
    del missing['fields']['CommandLine']
    dns=copy.deepcopy(whoami)
    dns.update(event_id=22,timestamp='2026-10-19T00:00:08Z',record_id='8')
    dns['fields']={key:whoami['fields'][key] for key in ('ProcessGuid','ProcessId')}
    dns['fields']['QueryName']='example.invalid'
    sensor=copy.deepcopy(dns)
    sensor.update(event_id=255,fields={'Error':'Synthetic sensor failure'})
    unsupported=copy.deepcopy(dns)
    unsupported.update(event_id=7,fields={'ImageLoaded':r'C:\Lab\inert.dll'})

    # Expected outcomes are fixed before calling the detector, not inferred from results.
    cases=[
        ('certutil_download',[certutil],'matched',('matched','no_match')),
        ('whoami_groups',[whoami],'matched',('no_match','matched')),
        ('benign_controls',benign,'no_match',('no_match','no_match')),
        ('missing_command',[missing],'incomplete',('field_incompatible','no_match')),
        ('no_process_create',[dns],'not_observed',('not_observed','not_observed')),
        ('sensor_error',[sensor],'incomplete',('not_observed','not_observed')),
        ('unsupported_event',[unsupported],'incomplete',('not_observed','not_observed')),
        ('chain',[*chain,whoami,dns],'matched',('matched','matched')),
    ]
    output.mkdir(parents=True,mode=0o700)
    env={**os.environ,'PYTHONPATH':str(ROOT/'backend'),'PYTHONDONTWRITEBYTECODE':'1'}
    results=[]
    for name,events,status,rule_states in cases:
        data=(json.dumps({'events':events},ensure_ascii=False,indent=2)+'\n').encode()
        source=output/(name+'.json')
        report_path=output/(name+'.report.json')
        source.write_bytes(data)
        # Only this fixed Python module is launched; no imported field enters the command.
        subprocess.run([sys.executable,'-B','-m','aegisav.behavior_cli',str(source),
                        '--output',str(report_path)],env=env,cwd=ROOT,
                       capture_output=True,check=True,timeout=30)
        report=json.loads(report_path.read_bytes())
        actual={rule['rule_id']:rule['status'] for rule in report['rules']}
        expected=dict(zip((CERTUTIL,WHOAMI),rule_states))
        passed=(report['status']==status and actual==expected and
                report['static_policy_modified'] is False and
                report['static_link']['status']=='not_linked')
        results.append(dict(name=name,status=report['status'],rules=actual,
            expected_status=status,expected_rules=expected,passed=passed,
            events=len(report['events']),processes=len(report['processes']),
            input_sha256=hashlib.sha256(data).hexdigest()))
    summary=dict(schema=1,synthetic_only=True,program_execution=False,accuracy_evaluation=False,
        interpretation='Fixed replay expectations validate wiring, not malware detection accuracy',
        rule_manifest_sha256=hashlib.sha256((ROOT/'rules/sigma/manifest.json').read_bytes()).hexdigest(),
        cases=results)
    (output/'summary.json').write_text(json.dumps(summary,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(cases=len(results),passed=sum(row['passed'] for row in results))))
    return 0 if all(row['passed'] for row in results) else 1


if __name__=='__main__': raise SystemExit(main())
