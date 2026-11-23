"""Harmless collection-mode proof, using a previously observed signed Windows DLL."""
import hashlib
import json
import os
from pathlib import Path
import sys
import time
import urllib.request
import urllib.error
sys.path.insert(0, '/opt/aegisav-collection')
sys.path.insert(0, '/opt/aegisav-collection/deps')
from collect_malwarebazaar import ROOT, RELEASE, network, save, NoRedirect
from collection_boundary import unpack_verified

SHA = 'c77aa0bc43913e8da4d98f22c326d716617021bd2f6afbf1030749f296738cc5'


def main():
    action = sys.argv[1]
    if action == 'prepare':
        assert os.getuid()==0
        import grp,pwd
        import pyzipper
        paths = list(Path('/opt/aegisav-benign/windows/samples').glob(SHA+'.*'))
        assert len(paths) == 1
        data = paths[0].read_bytes()
        assert hashlib.sha256(data).hexdigest() == SHA
        with pyzipper.AESZipFile(ROOT/'incoming'/'harmless-probe.zip','w',compression=pyzipper.ZIP_DEFLATED,encryption=pyzipper.WZ_AES) as package:
            package.setpassword(b'infected')
            package.writestr('harmless.bin',data)
        (ROOT/'incoming'/'harmless-probe.zip').chmod(0o640)
        os.chown(ROOT/'incoming'/'harmless-probe.zip',1002,grp.getgrnam('aegisav-corpus').gr_gid)
        (ROOT/'results'/'persistence-before.txt').write_text('harmless baseline marker\n')
        os.chown(ROOT/'results'/'persistence-before.txt',1001,pwd.getpwnam('aegisav-operator').pw_gid)
    elif action == 'online':
        assert os.getuid() == 1002
        report = dict(network=network('online'), raw_malware_used=False)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        try:
            with opener.open('https://mb-api.abuse.ch/api/v1/',timeout=20) as response:
                report.update(http_status=response.status,tls_verified=True)
                response.read(4096)
        except urllib.error.HTTPError as error:
            # The POST-only endpoint can reject GET while proving verified TLS connectivity.
            if error.code not in (401,405):
                raise
            report.update(http_status=error.code,tls_verified=True,request='unauthenticated_GET_transport_probe')
        save(ROOT/'incoming'/'online-probe.json', report)
    else:
        assert os.getuid() == 1001
        report = dict(isolation=network('offline'),raw_malware_used=False)
        raw = ROOT/'raw'/'harmless-probe.bin'
        try:
            report['size_bytes'] = unpack_verified((ROOT/'incoming'/'harmless-probe.zip').read_bytes(), SHA,raw,1024**2)
            sys.path.insert(0,str(RELEASE/'backend'))
            from aegisav.scanner import StaticScanner
            from aegisav.hashes import HashDatabase
            from aegisav.yara_engine import load_yara_engine
            from aegisav.clamav_engine import ClamAVEngine
            from aegisav.ml_engine import MLEngine
            scan = StaticScanner(HashDatabase.from_file(RELEASE/'rules/hashes.json'),load_yara_engine(RELEASE/'rules/yara',RELEASE/'rules/yara/metadata.json'),ClamAVEngine(),cache_capacity=0,ml_engine=MLEngine(RELEASE/'models/ember2024'))
            report['scan'] = scan.scan(raw.read_bytes())
            assert all(e['status']=='no_match' for e in report['scan']['engines'].values())
            report['marker_after_snapshot_survived'] = (ROOT/'results'/'persistence-after.txt').read_text()=='harmless post-snapshot marker\n'
            save(ROOT/'results'/'offline-probe.json',report)
        finally:
            raw.unlink(missing_ok=True)


if __name__=='__main__':
    main()
