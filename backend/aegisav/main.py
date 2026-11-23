from pathlib import Path
import hashlib
import os

from .api import create_app
from .runtime import build_scanner
from .local_access import load_access_token
from .scan_process import ProcessScanner


ROOT = Path(__file__).resolve().parents[2]


release_manifest = ROOT / 'release.json'
release_id = hashlib.sha256(release_manifest.read_bytes()).hexdigest()[:16] if release_manifest.exists() else None
key_root = Path(os.environ.get('LOCALAPPDATA', str(Path.home() / '.local/share'))) / 'AegisAV'
key_path = Path(os.environ.get('AEGISAV_ACCESS_TOKEN_FILE', str(key_root / 'local-access.key'))).resolve()
if key_path.is_relative_to(ROOT):
    raise ValueError('Access key must be stored outside the repository')
frontend = ROOT / 'frontend/out'
database_path = Path(os.environ.get('AEGISAV_TASK_DB', str(key_root / 'tasks.sqlite3'))).resolve()
if database_path.is_relative_to(ROOT):
    raise ValueError('Private task database must be stored outside the repository')
app = create_app(build_scanner(), release_id=release_id, access_token=load_access_token(key_path),
                 frontend_dir=frontend if (frontend/'index.html').exists() else None,
                 db_path=database_path, runner=ProcessScanner())
