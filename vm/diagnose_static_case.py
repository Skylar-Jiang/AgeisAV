"""Offline, bounded static case diagnosis; no PE execution and no policy changes."""
import hashlib
import json
import math
from pathlib import Path
import re
import sys


def aggregate_contributions(features,values):
    if len(values)!=sum(f.dim for f in features)+1 or not all(math.isfinite(float(x)) for x in values):
        raise ValueError('invalid_contribution_vector')
    offset=0;groups=[]
    for feature in features:
        end=offset+feature.dim
        groups.append(dict(name=feature.name,start=offset,end=end,raw_margin_contribution=float(sum(values[offset:end]))))
        offset=end
    return dict(groups=groups,expected_value=float(values[-1]),sum_raw_margin=float(sum(values)))


def pattern_probes(source):
    # This diagnostic supports the frozen Emotet rule's hex patterns only.
    match=re.search(r'(?ms)^\s*strings:\s*(.*?)^\s*condition:',source)
    if not match: raise ValueError('unsupported_rule_shape')
    body=match[1]
    patterns=re.findall(r'(?ms)^\s*\$([a-zA-Z0-9_]+)\s*=\s*(\{[^}]+\})',body)
    names=re.findall(r'(?m)^\s*\$([a-zA-Z0-9_]+)\s*=',body)
    if not names or names!=[p[0] for p in patterns] or len(names)!=len(set(names)):
        raise ValueError('unsupported_pattern_shape')
    return {name:'rule Probe_'+name+' { strings: $p = '+pattern+' condition: $p }' for name,pattern in patterns}


def bind_baseline(result,baseline):
    mismatch=[key for key in ('artifact_version','feature_schema','feature_implementation','feature_sha256')
              if result.get(key)!=baseline.get(key)]
    mismatch.extend(key for key in ('score','threshold','model_version')
                    if result['models']['general'].get(key)!=baseline.get(key))
    result.update(status='incompatible_baseline' if mismatch else 'completed',baseline_mismatches=mismatch,
                  baseline_feature_equal=result.get('feature_sha256')==baseline.get('feature_sha256'),
                  baseline_score_equal=result['models']['general']['score']==baseline.get('score'))


def worker(data,release,shadow_rules):
    import importlib.util
    import numpy as np
    import lightgbm as lgb
    import pefile,ppdeep,tlsh,yara_x
    from aegisav.pe import validate_pe
    from aegisav.hashes import HashDatabase,compute_fuzzy
    from aegisav.ml_engine import MLEngine,pe_scope
    from aegisav.ember_features import build_extractor
    from aegisav.yara_engine import load_yara_engine
    from aegisav.runtime import ROOT
    validate_pe(data)
    digest=hashlib.sha256(data).hexdigest()
    pe=pefile.PE(data=data,fast_load=False)
    exports=getattr(getattr(pe,'DIRECTORY_ENTRY_EXPORT',None),'symbols',[])
    result=dict(sha256=digest,script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        scope=pe_scope(data),size_bytes=len(data),machine=hex(pe.FILE_HEADER.Machine),
        optional_header_magic=hex(pe.OPTIONAL_HEADER.Magic),dll=bool(pe.FILE_HEADER.Characteristics&0x2000),
        timestamp=pe.FILE_HEADER.TimeDateStamp,warning_count=len(pe.get_warnings()),
        sections=[dict(name=s.Name.rstrip(b'\0').decode('ascii',errors='replace'),raw_size=s.SizeOfRawData,virtual_size=s.Misc_VirtualSize,entropy=s.get_entropy(),characteristics=hex(s.Characteristics)) for s in pe.sections],
        overlay_bytes=len(data)-(pe.get_overlay_data_start_offset() or len(data)),
        imported_modules=[e.dll.decode('ascii',errors='replace') for e in getattr(pe,'DIRECTORY_ENTRY_IMPORT',[])][:128],
        imported_function_count=sum(len(e.imports) for e in getattr(pe,'DIRECTORY_ENTRY_IMPORT',[])),
        export_count=len(exports),export_names=[s.name.decode('ascii',errors='replace') for s in exports[:32] if s.name],models={})
    assert result['scope']=='win64', 'This frozen case study expects the R3 Win64 input'
    registry=MLEngine(release/'models/ember2024');assert registry.probe()
    root=registry.root if hasattr(registry,'root') else release/'models/ember2024'
    spec=importlib.util.spec_from_file_location('pinned_features',root/'features.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    extractor=build_extractor(module,registry.manifest['feature_implementation'])
    vector=extractor.feature_vector(data)
    upstream=module.PEFeatureExtractor().feature_vector(data)
    assert vector.shape==(2568,) and np.isfinite(vector).all()
    result['upstream_full_vector_equal']=bool(np.array_equal(vector,upstream))
    result['feature_sha256']=hashlib.sha256(vector.astype('<f4').tobytes()).hexdigest()
    result['feature_schema']=registry.manifest['files']['features.py']
    result['feature_implementation']=registry.manifest['feature_implementation']
    result['artifact_version']=registry.artifact_version
    for name,entry in registry.manifest['models'].items():
        model=lgb.Booster(model_file=str(root/entry['file']));assert model.num_feature()==len(vector)
        score=float(model.predict(vector.reshape(1,-1),num_threads=1)[0])
        margin=float(model.predict(vector.reshape(1,-1),raw_score=True,num_threads=1)[0])
        values=model.predict(vector.reshape(1,-1),pred_contrib=True,num_threads=1)[0]
        contributions=aggregate_contributions(extractor.features,values)
        assert math.isclose(contributions['sum_raw_margin'],margin,abs_tol=1e-6)
        assert math.isclose(1/(1+math.exp(-margin)),score,abs_tol=1e-12)
        result['models'][name]=dict(score=score,threshold=entry['threshold'],model_version=entry['version'],raw_margin=margin,
            contribution_scope='TreeSHAP raw margin attribution; not a causal explanation or calibrated probability',**contributions)
    database=HashDatabase.from_file(ROOT/'rules/hashes.json');fp=compute_fuzzy(data)
    distances=[tlsh.diff(fp['tlsh'],r['tlsh']) for r in database.fuzzy_records if fp['tlsh'] and r.get('tlsh')]
    similarities=[ppdeep.compare(fp['ssdeep'],r['ssdeep']) for r in database.fuzzy_records if fp['ssdeep'] and r.get('ssdeep')]
    result['references']=dict(records=len(database.records),fuzzy_records=len(database.fuzzy_records),exact_present=digest in database.by_sha,
        minimum_tlsh_distance=min(distances,default=None),maximum_ssdeep_similarity=max(similarities,default=None),
        tlsh_threshold=40,ssdeep_threshold=80,
        tlsh_self_distance=tlsh.diff(fp['tlsh'],fp['tlsh']) if fp['tlsh'] else None,
        ssdeep_self_similarity=ppdeep.compare(fp['ssdeep'],fp['ssdeep']) if fp['ssdeep'] else None)
    result['yara']={}
    for label,directory in [('deployed',ROOT/'rules/yara'),('shadow',shadow_rules)]:
        metadata=json.loads((directory/'metadata.json').read_bytes())
        engine=load_yara_engine(directory,directory/'metadata.json')
        report=engine.scan(data)
        details=[]
        for entry in metadata:
            if entry.get('family')!='Emotet': continue
            source=(directory/entry.get('canonical_file',entry['rule_id']+'.yar')).read_text(encoding='utf-8')
            probes=pattern_probes(source)
            matches=[r.identifier.removeprefix('Probe_') for r in yara_x.compile('\n'.join(probes.values())).scan(data).matching_rules]
            details.append(dict(rule_id=entry['rule_id'],source=entry.get('source'),patterns=len(probes),matched_patterns=matches))
        result['yara'][label]=dict(rule_count=len(metadata),artifact=engine.artifact_version,status=report['status'],evidence=report['evidence'],emotet_pattern_probes=details)
    extra=Path(__file__).resolve().parent/'elastic-shadow/Emotet.yar'
    if extra.is_file():
        source=extra.read_bytes();compiled=yara_x.compile(source.decode('utf-8'))
        scanner=yara_x.Scanner(compiled);scanner.set_timeout(2)
        extra_result=dict(source_sha256=hashlib.sha256(source).hexdigest(),production_activated=False,
                          license='Elastic License 2.0; internal research only')
        try:
            matches=[r.identifier for r in scanner.scan(data).matching_rules]
            extra_result.update(status='matched' if matches else 'no_match',matches=matches)
        except yara_x.TimeoutError: extra_result.update(status='timeout',matches=None)
        result['yara']['elastic_research']=extra_result
    return result


def main():
    import os,threading,time,subprocess
    from aegisav.scan_process import ProcessScanner,contain_worker
    assert sys.platform=='linux' and os.getuid()==1001
    if sys.argv[1]=='worker':
        contain_worker()
        data=sys.stdin.buffer.read(2*1024**2+1);assert len(data)<=2*1024**2
        print(json.dumps(dict(report=worker(data,Path('/opt/aegisav-product/current'),Path(sys.argv[2]))),allow_nan=False));return
    isolation=subprocess.check_output(['/usr/local/bin/aegisav-isolation-check'],text=True).strip()
    baseline=Path(sys.argv[1]);shadow=Path(sys.argv[2]);output=Path(sys.argv[3]);assert not output.exists()
    record=next(r for r in json.loads(baseline.read_bytes())['files'] if r['status']=='completed')
    raw=baseline.parent.parent/'raw'/(record['sha256']+'.bin')
    assert raw.resolve().is_relative_to(Path('/srv/aegisav-corpus'))
    data=raw.read_bytes();assert hashlib.sha256(data).hexdigest()==record['sha256']
    runner=ProcessScanner([sys.executable,__file__,'worker',str(shadow)],memory_bytes=1536*1024**2)
    result=runner.scan(data,threading.Event(),time.monotonic()+120)
    old=record['report']['engines']['lightgbm']
    bind_baseline(result,old)
    result.update(isolation=isolation,baseline_sha256=hashlib.sha256(baseline.read_bytes()).hexdigest(),production_modified=False)
    from stage_e_checkpoint import persist
    persist(output,result)
    print(json.dumps(dict(status=result['status'],baseline_feature_equal=result['baseline_feature_equal'],baseline_score_equal=result['baseline_score_equal'],upstream_full_vector_equal=result['upstream_full_vector_equal'],scope=result['scope'])))


if __name__=='__main__':
    sys.excepthook=sys.__excepthook__
    main()
