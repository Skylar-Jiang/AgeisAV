"""Separate report journal: no raw logs, no auto-resume, no static schema changes."""
import json
import os
from pathlib import Path
import shutil
import sqlite3
from threading import Lock


class BehaviorStore:
    def __init__(self, path=None):
        self.lock=Lock()
        self.path=Path(path) if path else None
        if self.path:
            self.path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        self.db=sqlite3.connect(self.path or ':memory:',timeout=5,check_same_thread=False)
        try:
            if self.path and os.name!='nt': os.chmod(self.path,0o600)
            self.db.execute('PRAGMA busy_timeout=5000')
            if self.db.execute('PRAGMA quick_check').fetchone()[0]!='ok':
                raise sqlite3.DatabaseError('Behavior database integrity failed')
            version=self.db.execute('PRAGMA user_version').fetchone()[0]
            if version not in (0,1):
                raise sqlite3.DatabaseError('Unsupported behavior database schema')
            self.db.execute('PRAGMA journal_mode=WAL')
            self.db.execute('PRAGMA synchronous=FULL')
            if version==0:
                self.db.executescript('''BEGIN IMMEDIATE;
                    CREATE TABLE behavior_reports(id TEXT PRIMARY KEY, created_at TEXT NOT NULL,
                        status TEXT NOT NULL, source_sha256 TEXT NOT NULL, linked_sha256 TEXT,
                        report_json TEXT NOT NULL);
                    CREATE INDEX behavior_created ON behavior_reports(created_at DESC,id);
                    CREATE INDEX behavior_link ON behavior_reports(linked_sha256);
                    PRAGMA user_version=1; COMMIT;''')
        except BaseException:
            self.db.close()
            raise

    def save(self, report):
        with self.lock, self.db:
            allocated=self.db.execute('PRAGMA page_count').fetchone()[0]*self.db.execute('PRAGMA page_size').fetchone()[0]
            if allocated>128*1024**2 or (self.path and shutil.disk_usage(self.path.parent).free<512*1024**2):
                raise OverflowError('Behavior storage reserve reached; back up and review retention')
            if not self.path and self.db.execute('SELECT count(*) FROM behavior_reports').fetchone()[0]>=32:
                raise OverflowError('In-memory behavior report limit reached; configure persistent storage')
            self.db.execute('INSERT INTO behavior_reports VALUES (?,?,?,?,?,?)',
                (report['id'],report['created_at'],report['status'],report['source']['sha256'],
                 report['static_link'].get('sha256'),json.dumps(report,ensure_ascii=False)))

    def get(self, identity):
        with self.lock:
            row=self.db.execute('SELECT report_json FROM behavior_reports WHERE id=?',(identity,)).fetchone()
            return json.loads(row[0]) if row else None

    def list(self, limit, offset, sha256=None):
        with self.lock:
            where=' WHERE linked_sha256=?' if sha256 else ''
            parameters=([sha256] if sha256 else [])+[limit,offset]
            return [dict(id=r[0],created_at=r[1],status=r[2],source_sha256=r[3],linked_sha256=r[4])
                for r in self.db.execute('SELECT id,created_at,status,source_sha256,linked_sha256 FROM behavior_reports'+
                    where+' ORDER BY created_at DESC,id LIMIT ? OFFSET ?',parameters)]

    def close(self):
        with self.lock:
            self.db.close()
