from pathlib import Path
import hashlib
import os

from .api import create_app
from .clamav_engine import ClamAVEngine
from .hashes import HashDatabase
from .scanner import StaticScanner
from .yara_engine import load_yara_engine
from .ml_engine import MLEngine


ROOT = Path(__file__).resolve().parents[2]


def build_scanner() -> StaticScanner:
    rule_dir = ROOT / "rules" / "yara"
    yara_engine = None
    if any(rule_dir.glob("*.yar")):
        yara_engine = load_yara_engine(rule_dir, rule_dir / "metadata.json")
    clamav = ClamAVEngine()
    clamav.probe()
    return StaticScanner(
        HashDatabase.from_file(ROOT / "rules" / "hashes.json"),
        yara_engine=yara_engine,
        clamav_engine=clamav,
        ml_engine=MLEngine(os.environ.get('AEGISAV_MODEL_DIR', str(ROOT / 'models/ember2024')),
                           profile=os.environ.get('AEGISAV_ML_PROFILE', 'general'),
                           python_executable=os.environ.get('AEGISAV_ML_PYTHON')),
    )


release_manifest = ROOT / 'release.json'
release_id = hashlib.sha256(release_manifest.read_bytes()).hexdigest()[:16] if release_manifest.exists() else None
app = create_app(build_scanner(), release_id=release_id)
