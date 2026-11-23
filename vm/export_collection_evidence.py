"""Guest-side JSON boundary: raw bytes never cross into the host export channel."""
import argparse
import json
import os
from pathlib import Path
import stat

EXPANSION='/srv/aegisav-corpus/cohorts/76816a606721f48e00f696a5f265409aa72b9d5182672f24f46952075dc4b221'
PATHS=dict(Probe='/srv/aegisav-corpus/results/offline-probe.json',
           NativeParity='/home/aegisav-operator/native-pilot-parity.json',
           FuzzyBenchmark='/home/aegisav-operator/native-fuzzy-benchmark.json',
           ExpansionDownload=EXPANSION+'/incoming/download.json',
           Acquisition=EXPANSION+'/results/analysis.json',
           ExpansionScan=EXPANSION+'/results/development-scan-v1/analysis.json',
           ExpansionResources='/home/ubuntu/expansion-scan-resources.json',
           Api='/srv/aegisav-corpus/results/api-proof.json',
           Checkpoint='/home/ubuntu/checkpoint-before-resume.json',
           Failures='/home/ubuntu/collection-failures.json',
           OnlineProbe='/srv/aegisav-corpus/incoming/online-probe.json',
           Download='/srv/aegisav-corpus/incoming/download.json',
           Analysis='/srv/aegisav-corpus/results/analysis.json',
           Environment='/home/ubuntu/collection-environment.json')


def canonical_evidence(content,kind):
    if kind not in PATHS or len(content)>20*1024**2:
        raise ValueError('export_boundary')
    def invalid_constant(value):
        raise ValueError('nonfinite_json')
    value=json.loads(content,parse_constant=invalid_constant)
    if not isinstance(value,dict):
        raise ValueError('export_object_required')
    if kind in ('Download','Analysis','ExpansionDownload','Acquisition','ExpansionScan') and (not isinstance(value.get('identity'),dict) or not isinstance(value.get('files'),list)):
        raise ValueError('export_schema')
    if kind=='Probe' and not isinstance(value.get('scan'),dict):
        raise ValueError('export_probe_schema')
    if kind=='OnlineProbe' and value.get('tls_verified') is not True:
        raise ValueError('export_online_schema')
    if kind=='Environment' and not isinstance(value.get('volumes'),dict):
        raise ValueError('export_environment_schema')
    return (json.dumps(value,indent=2,allow_nan=False)+'\n').encode()


def main():
    import resource
    assert os.getuid()==0
    resource.setrlimit(resource.RLIMIT_AS,(512*1024**2,)*2)
    resource.setrlimit(resource.RLIMIT_CPU,(5,)*2)
    parser=argparse.ArgumentParser()
    parser.add_argument('kind',choices=PATHS)
    args=parser.parse_args()
    fd=os.open(PATHS[args.kind],os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as source:
        attributes=os.fstat(source.fileno())
        if not stat.S_ISREG(attributes.st_mode) or attributes.st_size>20*1024**2:
            raise ValueError('export_file_boundary')
        result=canonical_evidence(source.read(20*1024**2+1),args.kind)
    output=Path('/home/ubuntu/collection-export.json')
    output.unlink(missing_ok=True)
    with output.open('xb') as target:
        target.write(result)
    output.chmod(0o600)
    os.chown(output,1000,1000)


if __name__=='__main__':
    main()
