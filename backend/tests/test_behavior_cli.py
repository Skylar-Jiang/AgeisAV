import json
import os
from pathlib import Path
import subprocess
import sys

ENV={**os.environ,'PYTHONPATH':str(Path(__file__).resolve().parents[1])}


def test_real_cli_safe_output_and_no_overwrite(tmp_path):
    source=tmp_path/'inert.json'; source.write_text('{"events":[]}',encoding='utf-8')
    output=tmp_path/'report.json'
    command=[sys.executable,'-m','aegisav.behavior_cli',str(source),'--output',str(output)]
    first=subprocess.run(command,capture_output=True,timeout=15,env=ENV)
    assert first.returncode==0, first.stderr
    assert json.loads(output.read_bytes())['status']=='not_observed'
    assert json.loads(first.stdout)=={'status':'not_observed','events':0,'matches':0}
    assert subprocess.run(command,capture_output=True,timeout=15,env=ENV).returncode!=0
    assert output.exists()


def test_cli_invalid_log_and_repository_output_rejected(tmp_path):
    source=tmp_path/'bad.xml'; source.write_text('<!DOCTYPE x><Events/>',encoding='utf-8')
    output=tmp_path/'report.json'
    run=subprocess.run([sys.executable,'-m','aegisav.behavior_cli',str(source),'--output',str(output)],capture_output=True,timeout=15,env=ENV)
    assert run.returncode==2 and not output.exists()
    root=Path(__file__).resolve().parents[2]
    run=subprocess.run([sys.executable,'-m','aegisav.behavior_cli',str(source),'--output',str(root/'must-not-create.json')],capture_output=True,timeout=15,env=ENV)
    assert run.returncode==2 and not (root/'must-not-create.json').exists()
