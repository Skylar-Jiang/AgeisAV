"""Inert native fault injection under the real disposable Job, never a malware input."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'backend'))
SOURCE = r'''
#include <windows.h>
#include <stdint.h>
#include <string.h>
#ifndef ABI
#define ABI 1
#endif
__declspec(dllexport) uint32_t aegisav_ssdeep_abi(void) { return ABI; }
__declspec(dllexport) int aegisav_ssdeep(const char *p, size_t n, char *out, size_t cap) {
 if (cap<128) return -1;
 if(n && p[0]=='h') Sleep(90000);
 if(n && p[0]=='c') ExitProcess(7);
 if(n && p[0]=='m') {
  void *block=VirtualAlloc(NULL,256u*1024u*1024u,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
  if(block) { VirtualFree(block,0,MEM_RELEASE); return -1; }
  memcpy(out,"allocation-rejected",20); return 19;
 }
 memcpy(out,"3::",4); return 3;
}
'''


def worker(bundle, marker):
    from aegisav.scan_process import contain_worker
    contain_worker()
    from aegisav.native_ssdeep import NativeSSDeep
    data = sys.stdin.buffer.read(16)
    provider = NativeSSDeep(bundle)
    provider._load()
    Path(marker).write_text(str(__import__('os').getpid()))
    result = provider.hash(data)
    print(json.dumps({'report': {'native_output': result}}))


def main():
    import psutil
    from aegisav.scan_process import ProcessScanner
    from aegisav.tasks import ScanStopped
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compiler', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    python = ROOT / '.venv/Scripts/python.exe'
    bundles = {}
    for abi in (1, 2):
        bundle = args.output / ('ABI' + str(abi))
        bundle.mkdir()
        source = bundle / 'inert_fault.c'
        source.write_text(SOURCE)
        dll = bundle / 'aegisav_ssdeep.dll'
        subprocess.run([str(args.compiler), '-O2', '-shared', '-static-libgcc', '-DABI=' + str(abi),
                        str(source), '-o', str(dll)], check=True, capture_output=True)
        (bundle / 'manifest.json').write_text(json.dumps(dict(schema=1, abi=1,
            file=dll.name, sha256=hashlib.sha256(dll.read_bytes()).hexdigest())))
        bundles[abi] = bundle.resolve()
    result = {'inert_native_fault_injection_only': True, 'normal_detection_claim': False, 'checks': []}
    evidence = args.output / 'check.json'
    def save():
        evidence.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    try:
        for scenario, data, abi in (('abi_mismatch', b'n', 2), ('native_crash', b'c', 1),
                                     ('native_timeout', b'h', 1), ('native_cancel', b'h', 1),
                                     ('native_memory_limit', b'm', 1)):
            marker = (args.output / (scenario + '.pid')).resolve()
            code = f'from experiments.check_native_faults import worker; worker({str(bundles[abi])!r},{str(marker)!r})'
            scanner = ProcessScanner([str(python), '-B', '-c', code], memory_bytes=96 * 1024**2)
            cancel, waiter = threading.Event(), None
            if scenario == 'native_cancel':
                def canceller():
                    deadline = time.monotonic() + 10
                    while not marker.exists() and time.monotonic() < deadline:
                        time.sleep(.01)
                    if marker.exists():
                        time.sleep(.05)
                        cancel.set()
                waiter = threading.Thread(target=canceller)
                waiter.start()
            outcome = None
            try:
                response = scanner.scan(data, cancel, time.monotonic() + (1.5 if scenario == 'native_timeout' else 15))
                assert scenario == 'native_memory_limit' and response['native_output'] == 'allocation-rejected'
                outcome = 'allocation_rejected_by_96MiB_Job'
            except ScanStopped as error:
                assert str(error) == ('cancelled' if scenario == 'native_cancel' else 'timed_out')
                assert marker.exists(), 'Native library was not loaded before stopping'
                outcome = str(error)
            except RuntimeError:
                assert scenario in ('abi_mismatch', 'native_crash')
                outcome = 'error_without_negative_report'
            finally:
                if waiter:
                    waiter.join(timeout=10)
            assert scanner.healthy and scanner.active_pid is None
            if marker.exists():
                pid = int(marker.read_text())
                assert not psutil.pid_exists(pid)
            # The same controller accepts a fresh normal owned worker after failure.
            recovery = f'from experiments.check_native_faults import worker; worker({str(bundles[1])!r},{str(marker)!r})'
            scanner.command = [str(python), '-B', '-c', recovery]
            assert scanner.scan(b'n', threading.Event(), time.monotonic() + 10)['native_output'] == '3::'
            result['checks'].append({'scenario': scenario, 'outcome': outcome,
                                     'cleanup_confirmed': True, 'following_worker_recovered': True})
            save()
        result['completed'] = True
    except Exception as error:
        result.update(completed=False, exception_type=type(error).__name__, message=str(error))
        raise
    finally:
        save()
    print(json.dumps(result))


if __name__ == '__main__':
    main()
