"""Portable Windows controller. No installers, global dependencies or PID killing."""
import argparse
from contextlib import contextmanager
import ctypes
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
import webbrowser

APP=Path(__file__).resolve().parents[2]
PACKAGE=APP.parent


def relative_file(name):
    if not isinstance(name,str) or not name or '\\' in name or ':' in name:
        raise ValueError('Unsafe package path')
    path=Path(name)
    if path.is_absolute() or any(part in ('.','..') for part in name.split('/')):
        raise ValueError('Unsafe package path')
    return path


def verify_package(root):
    root=Path(root).resolve()
    raw=(root/'PACKAGE_MANIFEST.json').read_bytes()
    manifest=json.loads(raw)
    if manifest['schema']!=1 or not 1<=len(manifest['files'])<=10000:
        raise ValueError('Unsupported package manifest')
    expected={'PACKAGE_MANIFEST.json'}
    for name,digest in manifest['files'].items():
        target=root/relative_file(name)
        if not target.resolve().is_relative_to(root) or not target.is_file() or target.is_symlink() or hashlib.sha256(target.read_bytes()).hexdigest()!=digest:
            raise ValueError('Package integrity check failed: '+name)
        expected.add(name)
    actual={p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file()}
    if actual!=expected:
        raise ValueError('Package integrity failed: unexpected/missing files; re-extract a clean copy')
    return dict(manifest,package_id=hashlib.sha256(raw).hexdigest()[:24])


def private_root(package, location=None):
    root=Path(location or Path(os.environ['LOCALAPPDATA'])/'AegisAVDesktop').resolve()
    if root.is_relative_to(Path(package).resolve()) or root==Path(root.anchor):
        raise ValueError('Private profile must be outside package')
    marker=root/'desktop-profile-v1'
    if root.exists() and any(root.iterdir()) and not marker.is_file():
        raise ValueError('Profile is not an AegisAV desktop directory; choose a new empty path')
    root.mkdir(parents=True,exist_ok=True,mode=0o700)
    if os.name=='nt':
        if ctypes.WinDLL('shell32').IsUserAnAdmin():
            raise ValueError('Start as a normal user, not administrator')
        whoami=Path(os.environ['SystemRoot'])/'System32/whoami.exe'
        import csv
        identity=list(csv.reader([subprocess.check_output([str(whoami),'/user','/fo','csv','/nh'],text=True).strip()]))[0][1]
        if not identity.startswith('S-1-5-'): raise ValueError('Cannot identify profile owner')
        restrict_profile(root,identity)
    marker.touch(exist_ok=True)
    return root


def restrict_profile(root,identity):
    """Replace the owned profile's DACL, including existing explicit child grants."""
    from ctypes import wintypes as w
    api=ctypes.WinDLL('advapi32',use_last_error=True)
    convert=api.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes=[w.LPCWSTR,w.DWORD,ctypes.POINTER(ctypes.c_void_p),ctypes.POINTER(w.DWORD)]
    convert.restype=w.BOOL
    get_dacl=api.GetSecurityDescriptorDacl
    get_dacl.argtypes=[ctypes.c_void_p,ctypes.POINTER(w.BOOL),ctypes.POINTER(ctypes.c_void_p),ctypes.POINTER(w.BOOL)]
    get_dacl.restype=w.BOOL
    set_dacl=api.SetNamedSecurityInfoW
    set_dacl.argtypes=[w.LPWSTR,w.DWORD,w.DWORD,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p]
    set_dacl.restype=w.DWORD
    free=ctypes.WinDLL('kernel32').LocalFree;free.argtypes=[ctypes.c_void_p]
    paths=[root,*root.rglob('*')]
    if any(p.lstat().st_file_attributes&0x400 for p in paths):
        raise ValueError('Private profile must not contain reparse points')
    for path in paths:
        flags='OICI' if path.is_dir() else ''
        descriptor=ctypes.c_void_p();dacl=ctypes.c_void_p();present=w.BOOL();default=w.BOOL()
        if not convert(f'D:P(A;{flags};FA;;;{identity})(A;{flags};FA;;;SY)',1,ctypes.byref(descriptor),None):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            if not get_dacl(descriptor,ctypes.byref(present),ctypes.byref(dacl),ctypes.byref(default)):
                raise ctypes.WinError(ctypes.get_last_error())
            error=set_dacl(str(path),1,0x80000004,None,None,dacl,None)
            if error: raise ctypes.WinError(error)
        finally: free(descriptor)


def read_config(root):
    path=root/'config.json'
    if not path.exists(): return {}
    if path.stat().st_size>4096: raise ValueError('Optional config too large')
    value=json.loads(path.read_bytes())
    if not isinstance(value,dict) or set(value)-{'model_dir','ml_python'}:
        raise ValueError('Unsupported private configuration')
    if bool(value.get('model_dir'))!=bool(value.get('ml_python')):
        raise ValueError('Provide both model_dir and ml_python')
    for path in value.values():
        if not isinstance(path,str) or not Path(path).is_absolute():
            raise ValueError('Optional component paths must be absolute')
    return value


def preflight(profile, memory_bytes=None, disk_bytes=None):
    if memory_bytes is None:
        class Memory(ctypes.Structure):
            _fields_=[('length',ctypes.c_ulong),('load',ctypes.c_ulong)]+[(n,ctypes.c_ulonglong) for n in
                ('total_phys','available_phys','total_page','available_page','total_virtual','available_virtual','reserved')]
        info=Memory();info.length=ctypes.sizeof(info)
        if not ctypes.WinDLL('kernel32').GlobalMemoryStatusEx(ctypes.byref(info)):
            raise ValueError('Cannot verify memory availability')
        memory_bytes=info.available_phys
    if disk_bytes is None: disk_bytes=shutil.disk_usage(profile).free
    if memory_bytes<3*1024**3: raise ValueError('At least 3 GiB available host memory required; no other processes were stopped')
    if disk_bytes<512*1024**2: raise ValueError('At least 512 MiB free disk required')


@contextmanager
def control_lock(profile,name='control.lock'):
    import msvcrt
    with (profile/name).open('a+b') as stream:
        if stream.tell()==0: stream.write(b'0');stream.flush()
        stream.seek(0)
        try: msvcrt.locking(stream.fileno(),msvcrt.LK_NBLCK,1)
        except OSError as error: raise ValueError('Another desktop action is in progress; retry shortly') from error
        try: yield
        finally: stream.seek(0);msvcrt.locking(stream.fileno(),msvcrt.LK_UNLCK,1)


def service_running(profile):
    try:
        with control_lock(profile,'service.lock'): return False
    except ValueError: return True


def control_request(port,key,method='GET',path='/v1/desktop/status'):
    request=urllib.request.Request(f'http://127.0.0.1:{port}'+path,method=method,
                                   headers={'Authorization':'Bearer '+key})
    # Explicit no-proxy loopback transport; never send the local key through a proxy.
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request,timeout=2) as response: return json.loads(response.read(16384))


def atomic_json(path,value):
    temporary=path.with_suffix('.tmp')
    temporary.write_text(json.dumps(value,indent=2)+'\n',encoding='utf-8')
    temporary.replace(path)


def serve(profile,port,instance):
    # Lease survives listener closure until task/database shutdown has completed.
    with control_lock(profile,'service.lock'):
        state=json.loads((profile/'instance.json').read_bytes())
        if state['instance']!=instance:
            raise ValueError('Pending startup superseded; no service started')
        run_server(profile,port,instance)


def run_server(profile,port,instance):
    import logging.config
    import uvicorn
    from fastapi.staticfiles import StaticFiles
    from .api import create_app
    from .local_access import load_access_token
    from .runtime import build_scanner
    from .scan_process import ProcessScanner
    manifest=verify_package(PACKAGE)
    config=read_config(profile)
    # The bundled interpreter ignores these, but optional external ML Python
    # would otherwise inherit a host PYTHONHOME/PYTHONPATH and fail or import it.
    for name in list(os.environ):
        if name.upper().startswith('PYTHON'): os.environ.pop(name,None)
    # Only the two reviewed component paths are accepted, no key or execution-policy fields.
    for name in ('AEGISAV_MODEL_DIR','AEGISAV_ML_PYTHON','AEGISAV_ML_PROFILE'):
        os.environ.pop(name,None)
    if config:
        os.environ['AEGISAV_MODEL_DIR']=config['model_dir']
        os.environ['AEGISAV_ML_PYTHON']=config['ml_python']
    os.environ['PYTHONDONTWRITEBYTECODE']='1'
    key=load_access_token(profile/'local-access.key')
    scanner=build_scanner()
    app=create_app(scanner,release_id=manifest['package_id'],access_token=key,db_path=profile/'tasks.sqlite3',
        runner=ProcessScanner([sys.executable,'-B','-m','aegisav.scan_worker']),
        behavior_runner=ProcessScanner([sys.executable,'-B','-m','aegisav.behavior_worker'],memory_bytes=256*1024**2))
    server=uvicorn.Server(uvicorn.Config(app,host='127.0.0.1',port=port,proxy_headers=False,access_log=False,
        log_config={'version':1,'disable_existing_loggers':False,'handlers':{'private':{
            'class':'logging.handlers.RotatingFileHandler','filename':str(profile/'service.log'),
            'maxBytes':1024**2,'backupCount':1,'encoding':'utf-8'}},
            'root':{'handlers':['private'],'level':'INFO'},'loggers':{'uvicorn':{'handlers':['private'],'level':'INFO','propagate':False}}}))
    @app.get('/v1/desktop/status')
    def status():
        return dict(instance=instance,package_id=manifest['package_id'],version=manifest['version'],pid=os.getpid())
    @app.post('/v1/desktop/stop')
    def stop():
        server.should_exit=True
        return {'stopping':True,'instance':instance}
    app.mount('/',StaticFiles(directory=APP/'frontend/out',html=True))
    server.run()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=['start','stop','status','serve','key','configure','verify'])
    parser.add_argument('--data-dir',type=Path)
    parser.add_argument('--port',type=int,default=3417)
    parser.add_argument('--instance',default='')
    parser.add_argument('--no-browser',action='store_true')
    parser.add_argument('--model-dir',type=Path)
    parser.add_argument('--ml-python',type=Path)
    args=parser.parse_args()
    try:
        if os.name!='nt': raise ValueError('Portable desktop controller supports Windows x64 only')
        if not 1024<=args.port<=65535: raise ValueError('Port must be between 1024 and 65535')
        if args.action=='verify':
            manifest=verify_package(PACKAGE);print(json.dumps({'integrity':'ok','version':manifest['version']}));return 0
        profile=private_root(PACKAGE,args.data_dir)
        if args.action=='serve':
            serve(profile,args.port,args.instance);return 0
        with control_lock(profile):
            from .local_access import load_access_token
            key=load_access_token(profile/'local-access.key')
            if args.action=='key':
                subprocess.Popen([str(Path(os.environ['SystemRoot'])/'System32/notepad.exe'),str(profile/'local-access.key')])
                return 0
            manifest=verify_package(PACKAGE)
            if args.action=='configure':
                if not args.model_dir or not args.ml_python: raise ValueError('Both external model and ML Python paths required')
                from .ml_engine import MLEngine
                model=MLEngine(args.model_dir,python_executable=str(args.ml_python))
                if not args.ml_python.is_file() or not model.probe(): raise ValueError('Existing model registry or Python not valid')
                atomic_json(profile/'config.json',dict(model_dir=str(args.model_dir.resolve()),ml_python=str(args.ml_python.resolve())))
                print('External model paths saved privately; restart the service to apply.');return 0
            state=json.loads((profile/'instance.json').read_bytes()) if (profile/'instance.json').exists() else None
            if state:
                try:
                    active=control_request(state['port'],key)
                except urllib.error.HTTPError as error:
                    raise ValueError('Local service authentication/protocol failed; no shutdown confirmed') from error
                except (OSError,ValueError): active=None
                if active:
                    if active['package_id']!=manifest['package_id'] or active['instance']!=state['instance']:
                        raise ValueError('A different AegisAV instance owns this profile; use its Stop script')
                    if args.action=='stop':
                        response=control_request(state['port'],key,'POST','/v1/desktop/stop')
                        if response['instance']!=state['instance']: raise ValueError('Instance identity changed; no further action')
                        for _ in range(100):
                            if not service_running(profile):
                                print('AegisAV stopped; reports and key retained.');return 0
                            time.sleep(.1)
                        raise ValueError('Graceful stop not confirmed; inspect private service.log; no PID was killed')
                    print('AegisAV ready: http://127.0.0.1:'+str(state['port'])+'/linen/')
                    if args.action=='start' and not args.no_browser: webbrowser.open(f'http://127.0.0.1:{state["port"]}/linen/')
                    return 0
            if service_running(profile):
                raise ValueError('Profile service is starting, draining or unreachable; no second service was started')
            if args.action in ('stop','status'):
                print('AegisAV is not responding; no process was killed.');return 0 if args.action=='stop' else 1
            preflight(profile)
            with socket.socket() as probe:
                try: probe.bind(('127.0.0.1',args.port))
                except OSError as error: raise ValueError('Local port occupied; nothing was stopped. Choose --port or close its owner.') from error
            instance=uuid.uuid4().hex
            with control_lock(profile,'service.lock'):
                atomic_json(profile/'instance.json',dict(instance=instance,port=args.port,package_id=manifest['package_id']))
            child=subprocess.Popen([str(PACKAGE/'runtime/python.exe'),'-I','-B','-m','aegisav.desktop','serve',
                '--data-dir',str(profile),'--port',str(args.port),'--instance',instance],
                stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW,env={k:v for k,v in os.environ.items() if not any(s in k.upper() for s in ('TOKEN','PASSWORD','SECRET','AUTH_KEY','API_KEY'))})
            for _ in range(120):
                if child.poll() is not None: raise ValueError('Desktop service exited; inspect private service.log')
                try:
                    active=control_request(args.port,key)
                    if active['instance']==instance and active['package_id']==manifest['package_id']:
                        print(f'AegisAV ready: http://127.0.0.1:{args.port}/linen/')
                        print('First login: Access-Key.cmd opens the private local key; no key is printed or placed in a URL.')
                        if not args.no_browser: webbrowser.open(f'http://127.0.0.1:{args.port}/linen/')
                        return 0
                except (OSError,ValueError,KeyError): pass
                time.sleep(.25)
            # Only this newly created process handle is terminated, never a saved PID.
            child.terminate();child.wait(timeout=10)
            raise ValueError('Startup timed out; owned startup process stopped; pending state retained for diagnosis.')
    except (OSError,ValueError,KeyError,subprocess.SubprocessError) as error:
        print('AegisAV: '+str(error),file=sys.stderr)
        return 1


if __name__=='__main__': raise SystemExit(main())
