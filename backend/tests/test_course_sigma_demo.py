"""Exercise the course lab through the real bounded behavior CLI."""
import json
import os
from pathlib import Path
import subprocess
import sys


ROOT=Path(__file__).resolve().parents[2]
ENV={**os.environ,'PYTHONPATH':str(ROOT/'backend'),'PYTHONDONTWRITEBYTECODE':'1'}


def test_course_lab_replays_both_rules_and_telemetry_gaps(tmp_path):
    output=tmp_path/'course lab'
    command=[sys.executable,'-B','-m','experiments.course_sigma_demo',str(output)]
    run=subprocess.run(command,cwd=ROOT,env=ENV,capture_output=True,text=True,timeout=90)
    assert run.returncode==0, run.stderr
    summary=json.loads((output/'summary.json').read_bytes())
    assert summary['program_execution'] is False
    assert summary['accuracy_evaluation'] is False
    cases={case['name']:case for case in summary['cases']}
    assert len(cases)==8 and all(case['passed'] for case in cases.values())
    assert cases['certutil_download']['status']=='matched'
    assert cases['whoami_groups']['status']=='matched'
    assert cases['benign_controls']['status']=='no_match'
    assert cases['missing_command']['status']=='incomplete'
    assert cases['no_process_create']['status']=='not_observed'
    assert cases['sensor_error']['status']=='incomplete'
    assert cases['unsupported_event']['status']=='incomplete'
    report=json.loads((output/'chain.report.json').read_bytes())
    assert len(report['matches'])==2 and len(report['processes'])==3
    assert report['static_policy_modified'] is False
    assert report['static_link']['status']=='not_linked'
    assert all(match['author'] and match['asset_sha256'] for match in report['matches'])
    assert report['coverage']['completeness_proven'] is False
    again=subprocess.run(command,cwd=ROOT,env=ENV,capture_output=True,timeout=15)
    assert again.returncode!=0


def test_course_lab_rejects_output_inside_checkout():
    output=ROOT/'artifacts'/'must-not-create-course-demo'
    run=subprocess.run([sys.executable,'-B','-m','experiments.course_sigma_demo',str(output)],
                       cwd=ROOT,env=ENV,capture_output=True,timeout=15)
    assert run.returncode!=0 and not output.exists()
