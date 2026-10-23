import hashlib
import json
from pathlib import Path

import pytest
import os
import subprocess
import sys
import urllib.error
from contextlib import nullcontext
from unittest.mock import Mock

from experiments.build_windows_delivery import safe_member, app_sources, deterministic_zip
from aegisav.desktop import verify_package, preflight, private_root, read_config


def test_native_candidate_component_requires_reviewed_source_and_exact_dll(tmp_path):
    from experiments.build_windows_delivery import native_component
    bundle = tmp_path / 'native'
    bundle.mkdir()
    source = tmp_path / 'source'
    (source / 'experiments').mkdir(parents=True)
    (source / 'experiments/native_ssdeep.c').write_bytes(b'inert reviewed source')
    blob = b'inert DLL bytes only'
    (bundle / 'aegisav_ssdeep.dll').write_bytes(blob)
    manifest = dict(schema=1, abi=1, file='aegisav_ssdeep.dll', sha256='0' * 64,
                    source_sha256=hashlib.sha256(b'inert reviewed source').hexdigest())
    (bundle / 'manifest.json').write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match='digest'):
        native_component(bundle, source)


def test_package_backend_is_pinned_by_manifest_not_host_environment(monkeypatch, tmp_path):
    from aegisav import desktop, local_access, runtime
    monkeypatch.setenv('AEGISAV_SSDEEP_BACKEND', 'unrecognized-host-poison')
    monkeypatch.setattr(desktop, 'verify_package', lambda *_: {'package_id': 'fixture', 'ssdeep_backend': 'native'})
    monkeypatch.setattr(desktop, 'read_config', lambda *_: {})
    monkeypatch.setattr(local_access, 'load_access_token', lambda *_: 'inert-test-key')
    class Verified(Exception):
        pass
    def build():
        assert os.environ['AEGISAV_SSDEEP_BACKEND'] == 'native'
        raise Verified()
    monkeypatch.setattr(runtime, 'build_scanner', build)
    with pytest.raises(Verified):
        desktop.run_server(tmp_path, 3420, 'fixture')


def test_delivery_source_allowlist_excludes_private_material(tmp_path):
    for name in ['backend/aegisav/api.py','rules/sigma/manifest.json','rules/hashes.json',
                 'models/registry.json','docs/benchmarks/private.json','backend/tests/private.json',
                 'rules/private.key','rules/sample.exe']:
        p=tmp_path/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text('inert',encoding='utf-8')
    names={p.relative_to(tmp_path).as_posix() for p in app_sources(tmp_path)}
    assert names=={'backend/aegisav/api.py','rules/sigma/manifest.json','rules/hashes.json'}


@pytest.mark.parametrize('name',['../outside','/absolute','C:/outside','python/../../outside','python/x:stream','python/link/../escape'])
def test_runtime_archive_member_is_confined(name):
    with pytest.raises(ValueError):safe_member(name)


def test_package_integrity_and_deterministic_archive(tmp_path):
    root=tmp_path/'package';root.mkdir();(root/'app').mkdir();(root/'app/a.py').write_bytes(b'harmless')
    manifest={'schema':1,'version':'0.2.0','files':{'app/a.py':hashlib.sha256(b'harmless').hexdigest()}}
    (root/'PACKAGE_MANIFEST.json').write_text(json.dumps(manifest),encoding='utf-8')
    assert verify_package(root)['version']=='0.2.0'
    a,b=tmp_path/'a.zip',tmp_path/'b.zip'
    deterministic_zip(root,a);deterministic_zip(root,b)
    assert a.read_bytes()==b.read_bytes()
    (root/'app/a.py').write_bytes(b'tampered')
    with pytest.raises(ValueError,match='integrity'):verify_package(root)
    manifest['files']={'../outside':'0'*64}
    (root/'PACKAGE_MANIFEST.json').write_text(json.dumps(manifest),encoding='utf-8')
    with pytest.raises(ValueError):verify_package(root)


def test_preflight_fails_without_changing_resources(tmp_path):
    with pytest.raises(ValueError,match='memory'):preflight(tmp_path,memory_bytes=1024**3,disk_bytes=1024**3)
    with pytest.raises(ValueError,match='disk'):preflight(tmp_path,memory_bytes=8*1024**3,disk_bytes=100)
    preflight(tmp_path,memory_bytes=8*1024**3,disk_bytes=1024**3)


def test_reviewed_setuptools_hook_is_not_shipped(tmp_path,monkeypatch):
    from importlib.metadata import PackagePath
    from experiments import build_windows_delivery as delivery
    source=tmp_path/'source';source.mkdir()
    (source/'distutils-precedence.pth').write_text('not executed')
    dist=Mock();dist.files=[PackagePath('distutils-precedence.pth')];dist.version='82.0.1'
    dist.files[0].hash=None
    dist.metadata={'Name':'setuptools'};dist.locate_file=lambda p:source/str(p)
    monkeypatch.setattr(delivery,'dependencies',lambda:{'setuptools':dist})
    delivery.copy_dependencies(tmp_path/'package')
    assert not (tmp_path/'package/runtime/Lib/site-packages/distutils-precedence.pth').exists()


def test_private_profile_and_optional_config_are_bounded(tmp_path):
    package=tmp_path/'package';package.mkdir()
    with pytest.raises(ValueError):private_root(package,package/'data')
    profile=private_root(package,tmp_path/'private')
    assert profile.parent==tmp_path
    assert read_config(profile)=={}
    (profile/'config.json').write_text('{"api_key":"never accepted"}',encoding='utf-8')
    with pytest.raises(ValueError):read_config(profile)


@pytest.mark.skipif(os.name!='nt',reason='Windows profile DACL')
def test_existing_profile_explicit_public_acl_is_removed(tmp_path):
    package=tmp_path/'package';package.mkdir()
    profile=tmp_path/'profile';profile.mkdir()
    (profile/'desktop-profile-v1').touch();child=profile/'inert.txt';child.write_text('inert')
    for path in (profile,child):
        subprocess.run(['icacls.exe',str(path),'/grant','*S-1-1-0:F'],check=True,capture_output=True)
    private_root(package,profile)
    for index,path in enumerate((profile,child)):
        saved=tmp_path/f'acl{index}.txt'
        subprocess.run(['icacls.exe',str(path),'/save',str(saved),'/q'],check=True,capture_output=True)
        result=saved.read_text(encoding='utf-16-le')
        assert ';;;WD)' not in result
        assert ';;;SY)' in result


@pytest.mark.skipif(os.name!='nt',reason='Windows lifetime lock')
def test_service_lease_covers_listener_shutdown(tmp_path):
    from aegisav import desktop
    with desktop.control_lock(tmp_path,'service.lock'):
        assert desktop.service_running(tmp_path)
    assert not desktop.service_running(tmp_path)


@pytest.mark.skipif(os.name!='nt',reason='Windows service lease')
def test_superseded_pending_start_cannot_serve(monkeypatch,tmp_path):
    from aegisav import desktop
    (tmp_path/'instance.json').write_text(json.dumps({'instance':'newer-owned-start'}))
    run=Mock();monkeypatch.setattr(desktop,'run_server',run)
    with pytest.raises(ValueError,match='superseded'):desktop.serve(tmp_path,3426,'old-pending-start')
    run.assert_not_called()


def desktop_main_fixture(monkeypatch,tmp_path,action):
    from aegisav import desktop
    from aegisav import local_access
    monkeypatch.setattr(sys,'argv',['desktop',action,'--no-browser'])
    monkeypatch.setattr(desktop,'private_root',lambda *_:tmp_path)
    monkeypatch.setattr(desktop,'verify_package',lambda *_:{'package_id':'fixture','version':'0.2.0'})
    monkeypatch.setattr(desktop,'control_lock',lambda *_:nullcontext())
    monkeypatch.setattr(local_access,'load_access_token',lambda *_:'inert-test-access-key-never-credential')
    monkeypatch.setattr(desktop,'preflight',lambda *_:None)
    return desktop


@pytest.mark.skipif(os.name!='nt',reason='Windows controller')
def test_stop_authentication_failure_is_not_stopped(monkeypatch,tmp_path):
    desktop=desktop_main_fixture(monkeypatch,tmp_path,'stop')
    (tmp_path/'instance.json').write_text(json.dumps({'port':3426,'instance':'owned'}))
    monkeypatch.setattr(desktop,'control_request',Mock(side_effect=urllib.error.HTTPError('http://127.0.0.1',401,'Unauthorized',{},None)))
    assert desktop.main()==1


@pytest.mark.skipif(os.name!='nt',reason='Windows controller')
def test_startup_timeout_registers_and_reaps_only_owned_child(monkeypatch,tmp_path):
    desktop=desktop_main_fixture(monkeypatch,tmp_path,'start')
    child=Mock();child.poll.return_value=None
    monkeypatch.setattr(desktop.subprocess,'Popen',Mock(return_value=child))
    monkeypatch.setattr(desktop,'control_request',Mock(side_effect=ConnectionRefusedError()))
    monkeypatch.setattr(desktop.time,'sleep',lambda _:None)
    assert desktop.main()==1
    assert json.loads((tmp_path/'instance.json').read_bytes())['package_id']=='fixture'
    child.terminate.assert_called_once()
    child.wait.assert_called()


def test_external_ml_does_not_inherit_host_python_configuration(monkeypatch,tmp_path):
    from aegisav import desktop,local_access,runtime
    monkeypatch.setenv('PYTHONHOME',str(tmp_path/'poisoned'))
    monkeypatch.setenv('PYTHONPATH',str(tmp_path/'poisoned'))
    monkeypatch.setattr(desktop,'verify_package',lambda *_:{'package_id':'fixture'})
    monkeypatch.setattr(desktop,'read_config',lambda *_:{})
    monkeypatch.setattr(local_access,'load_access_token',lambda *_:'inert-fixture')
    def build():
        assert 'PYTHONHOME' not in os.environ
        assert 'PYTHONPATH' not in os.environ
        assert os.environ['PYTHONDONTWRITEBYTECODE']=='1'
        raise RuntimeError('stop fixture before server creation')
    monkeypatch.setattr(runtime,'build_scanner',build)
    with pytest.raises(RuntimeError,match='stop fixture'):desktop.run_server(tmp_path,3426,'fixture')
