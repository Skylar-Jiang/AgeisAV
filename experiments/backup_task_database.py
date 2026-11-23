"""Create a consistent private SQLite backup without deleting or replacing assets."""
import argparse
import os
from pathlib import Path
import sqlite3


def backup(source, destination):
    source, destination = Path(source).resolve(), Path(destination).resolve()
    root = Path(__file__).resolve().parents[1]
    if source.is_relative_to(root) or destination.is_relative_to(root):
        raise ValueError('Private task databases and backups must remain outside the repository')
    if not source.is_file():
        raise FileNotFoundError('Source database does not exist')
    destination.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    descriptor = os.open(destination,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    os.close(descriptor)
    # SQLite backup includes committed WAL changes; copying only the .sqlite3 file does not.
    reader = sqlite3.connect(source.as_uri()+'?mode=ro',uri=True,timeout=5)
    writer = sqlite3.connect(destination)
    try:
        if reader.execute('PRAGMA quick_check').fetchone()[0] != 'ok':
            raise sqlite3.DatabaseError('Source integrity check failed')
        reader.backup(writer,pages=128,sleep=.05)
        if writer.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
            raise sqlite3.DatabaseError('Backup integrity check failed')
    finally:
        writer.close()
        reader.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source')
    parser.add_argument('destination')
    args = parser.parse_args()
    backup(args.source,args.destination)
    print('Private task database backup verified; original preserved')
