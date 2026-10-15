from pathlib import Path
import hashlib
import os

from .api import create_app
from .clamav_engine import ClamAVEngine
from .hashes import HashDatabase
from .scanner import StaticScanner
from .yara_engine import load_yara_engine
from .ml_engine import MLEngine
from .local_access import load_access_token


ROOT = Path(__file__).resolve().parents[2]


def build_scanner() -> StaticScanner:
    rule_dir = ROOT / "rules" / "yara"
    yara_engine = None
    if any(rule_dir.glob("*.yar")):
        yara_engine = load_yara_engine(rule_dir, rule_dir / "metadata.json")
    clamav = ClamAVEngine()
    clamav.probe()
    local_ml_python = ROOT / '.venv-ml' / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')
    return StaticScanner(
        HashDatabase.from_file(ROOT / "rules" / "hashes.json"),
        yara_engine=yara_engine,
        clamav_engine=clamav,
        ml_engine=MLEngine(os.environ.get('AEGISAV_MODEL_DIR', str(ROOT / 'models/ember2024')),
                           profile=os.environ.get('AEGISAV_ML_PROFILE', 'general'),
                           python_executable=os.environ.get('AEGISAV_ML_PYTHON') or
                           (str(local_ml_python) if local_ml_python.exists() else None)),
    )


release_manifest = ROOT / 'release.json'
release_id = hashlib.sha256(release_manifest.read_bytes()).hexdigest()[:16] if release_manifest.exists() else None
key_root = Path(os.environ.get('LOCALAPPDATA', str(Path.home() / '.local/share'))) / 'AegisAV'
key_path = Path(os.environ.get('AEGISAV_ACCESS_TOKEN_FILE', str(key_root / 'local-access.key'))).resolve()
if key_path.is_relative_to(ROOT):
    raise ValueError('Access key must be stored outside the repository')
frontend = ROOT / 'frontend/out'
app = create_app(build_scanner(), release_id=release_id, access_token=load_access_token(key_path),
                 frontend_dir=frontend if (frontend/'index.html').exists() else None)
