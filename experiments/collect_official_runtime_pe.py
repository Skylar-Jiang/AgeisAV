"""Acquire fixed official Python/PuTTY benign candidates without execution or scoring."""
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path,PurePosixPath
import shutil
import urllib.request
import zipfile

from aegisav.ml_engine import pe_scope
from experiments.collect_benign_expansion import inspect_signatures,pe_metadata

SOURCES=[('python-amd64','https://www.python.org/ftp/python/3.13.9/python-3.13.9-embed-amd64.zip',
          'https://www.python.org/downloads/release/python-3139/','2025-10-14','Python Software Foundation'),
         ('python-win32','https://www.python.org/ftp/python/3.13.9/python-3.13.9-embed-win32.zip',
          'https://www.python.org/downloads/release/python-3139/','2025-10-14','Python Software Foundation'),
         ('putty-amd64','https://the.earth.li/~sgtatham/putty/0.83/w64/putty.zip',
          'https://www.chiark.greenend.org.uk/~sgtatham/putty/releases/0.83.html','2025-02-08','Simon Tatham')]


def main():
    root=Path(__file__).resolve().parents[1]
    output=root/'artifacts/official-runtime-pe-20261017'
    assert not output.exists(), 'Preserve frozen acquisition; use another version for retries'
    (output/'samples').mkdir(parents=True)
    rows=[];packages=[];errors=[];seen=set();prior=set()
    for path in (root/'docs/benchmarks').glob('*manifest*.jsonl'):
        prior.update(json.loads(line)['sha256'] for line in path.read_text(encoding='utf-8').splitlines() if line.strip())
    for name,url,page,date,publisher in SOURCES:
        package=output/(name+'.zip')
        try:
            with urllib.request.urlopen(url,timeout=60) as response,package.open('xb') as target:
                headers={key:response.headers.get(key) for key in ('Content-Length','Last-Modified','ETag')}
                total=0
                while chunk:=response.read(65536):
                    total+=len(chunk)
                    if total>32*1024**2: raise ValueError('package_budget')
                    target.write(chunk)
            if headers['Content-Length'] and total!=int(headers['Content-Length']): raise ValueError('incomplete_package')
            package_sha=hashlib.sha256(package.read_bytes()).hexdigest()
            packages.append(dict(name=name,url=url,page=page,release_date=date,bytes=total,sha256=package_sha,headers=headers))
            with zipfile.ZipFile(package) as archive:
                assert len(archive.infolist())<500 and sum(e.file_size for e in archive.infolist())<128*1024**2
                for entry in archive.infolist():
                    suffix=PurePosixPath(entry.filename).suffix.lower()
                    if suffix not in {'.exe','.dll','.pyd','.sys'}: continue
                    assert 0<entry.file_size<=16*1024**2
                    data=archive.read(entry);sha=hashlib.sha256(data).hexdigest()
                    if sha in seen: continue
                    seen.add(sha)
                    target=output/'samples'/(sha+suffix);target.write_bytes(data)
                    rows.append(dict(sha256=sha,size_bytes=len(data),source_path=str(target),path='samples/'+target.name,
                        original_member=entry.filename,source_url=url,source_page=page,package_sha256=package_sha,
                        package_release_date=date,first_seen_utc=None,acquired_utc=datetime.now(timezone.utc).isoformat(),
                        time_evidence='Official package release date; not verified global binary first-seen',
                        expected_publisher=publisher,pe_scope=pe_scope(data),prior_exact_overlap=sha in prior,
                        detector_results_observed=False,dataset_role='unscored_official_candidate',
                        label='presumed_benign',label_basis='Unmodified PE from publisher-linked HTTPS package; signature and purpose reviewed, not absolute truth',
                        purpose='language_runtime' if name.startswith('python') else 'authorized_ssh_administration',
                        **pe_metadata(data)))
        except Exception as error: errors.append(dict(package=name,error=type(error).__name__))
    shell=shutil.which('pwsh') or shutil.which('powershell')
    signed=[]
    for offset in range(0,len(rows),24): signed.extend(inspect_signatures(shell,rows[offset:offset+24]))
    manifest=output/'manifest.jsonl'
    manifest.write_text(''.join(json.dumps(row)+'\n' for row in signed),encoding='utf-8')
    result=dict(schema=1,packages=packages,files=len(signed),package_failures=errors,
                valid_signatures=sum(r['signature_status']=='Valid' for r in signed),
                expected_publisher_valid=sum(r['signature_status']=='Valid' and r['expected_publisher'] in r['signer'] for r in signed),
                prior_exact_overlap=sum(r['prior_exact_overlap'] for r in signed),raw_malware_used=False,
                detector_results_observed=False,manifest_sha256=hashlib.sha256(manifest.read_bytes()).hexdigest())
    (output/'acquisition.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(result))


if __name__=='__main__': main()
