"""Private local task journal. No uploaded bytes or credentials are persisted."""
import json
import os
from pathlib import Path
import sqlite3
import shutil


class TaskStore:
    def __init__(self, path):
        path = Path(path)
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.owner = open(str(path)+'.lock', 'a+b')
        self.connection = None
        try:
            self.owner.seek(0)
            if os.name == 'nt':
                import msvcrt
                if path.with_name(path.name+'.lock').stat().st_size == 0:
                    self.owner.write(b'0')
                    self.owner.flush()
                self.owner.seek(0)
                msvcrt.locking(self.owner.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.owner, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            self.owner.close()
            raise RuntimeError('Task database already in use by another service') from error
        try:
            self.connection = sqlite3.connect(path, timeout=5, check_same_thread=False)
            if os.name != 'nt':
                os.chmod(path, 0o600)
            self.connection.row_factory = sqlite3.Row
            self.connection.execute('PRAGMA foreign_keys=ON')
            self.connection.execute('PRAGMA busy_timeout=5000')
            if self.connection.execute('PRAGMA quick_check').fetchone()[0] != 'ok':
                raise sqlite3.DatabaseError('Task database integrity check failed')
            version = self.connection.execute('PRAGMA user_version').fetchone()[0]
            if version not in (0, 1):
                raise RuntimeError('Unsupported task database schema; preserve database and upgrade service')
            self.connection.execute('PRAGMA journal_mode=WAL')
            self.connection.execute('PRAGMA synchronous=FULL')
            if version == 0:
                self.connection.executescript('''
                    BEGIN IMMEDIATE;
                    CREATE TABLE tasks (
                        id TEXT PRIMARY KEY, status TEXT NOT NULL, created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL, deadline_at TEXT NOT NULL,
                        total INTEGER NOT NULL CHECK(total BETWEEN 1 AND 20),
                        finished INTEGER NOT NULL CHECK(finished BETWEEN 0 AND total),
                        cancel_requested INTEGER NOT NULL, request_fingerprint TEXT NOT NULL,
                        idempotency_key TEXT UNIQUE, service_release TEXT, error TEXT);
                    CREATE INDEX tasks_created ON tasks(created_at DESC, id);
                    CREATE INDEX tasks_status ON tasks(status);
                    CREATE TABLE task_files (
                        task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
                        ordinal INTEGER NOT NULL, name TEXT NOT NULL, size_bytes INTEGER NOT NULL,
                        status TEXT NOT NULL, report_json TEXT, error TEXT, elapsed_ms REAL,
                        duplicate_of INTEGER, updated_at TEXT NOT NULL,
                        PRIMARY KEY(task_id, ordinal));
                    CREATE TABLE task_events (
                        sequence INTEGER PRIMARY KEY, task_id TEXT NOT NULL REFERENCES tasks(id),
                        recorded_at TEXT NOT NULL, status TEXT NOT NULL, reason TEXT);
                    CREATE INDEX events_task ON task_events(task_id, sequence);
                    PRAGMA user_version=1;
                    COMMIT;
                ''')
        except BaseException:
            self.close()
            raise

    def save(self, job):
        # Caller serializes access. A report, file state and task progress commit together.
        with self.connection:
            previous = self.connection.execute('SELECT status FROM tasks WHERE id=?', (job['id'],)).fetchone()
            columns = ('id','status','created_at','updated_at','deadline_at','total','finished',
                       'cancel_requested','request_fingerprint','idempotency_key','service_release','error')
            self.connection.execute('INSERT INTO tasks VALUES ('+','.join('?' for _ in columns)+') '
                                    'ON CONFLICT(id) DO UPDATE SET '+','.join(c+'=excluded.'+c for c in columns[1:]),
                                    tuple(job.get(c) for c in columns))
            for index, row in enumerate(job['files']):
                self.connection.execute('INSERT INTO task_files VALUES (?,?,?,?,?,?,?,?,?,?) '
                                        'ON CONFLICT(task_id,ordinal) DO UPDATE SET '
                                        'status=excluded.status,report_json=excluded.report_json,error=excluded.error,'
                                        'elapsed_ms=excluded.elapsed_ms,duplicate_of=excluded.duplicate_of,updated_at=excluded.updated_at',
                                        (job['id'],index,row['name'],row['size_bytes'],row['status'],
                                         json.dumps(row['report'],ensure_ascii=False) if row['report'] is not None else None,
                                         row.get('error'),row.get('elapsed_ms'),row.get('duplicate_of'),job['updated_at']))
            if previous is None or previous['status'] != job['status']:
                self.connection.execute('INSERT INTO task_events(task_id,recorded_at,status,reason) VALUES (?,?,?,?)',
                                        (job['id'],job['updated_at'],job['status'],job.get('error')))

    def get(self, identity):
        row = self.connection.execute('SELECT * FROM tasks WHERE id=?', (identity,)).fetchone()
        if row is None:
            return None
        job = dict(row)
        job.update(persistent=True, cancel_requested=bool(job['cancel_requested']), files=[])
        for row in self.connection.execute('SELECT * FROM task_files WHERE task_id=? ORDER BY ordinal', (identity,)):
            item = {key:row[key] for key in ('name','size_bytes','status','error')}
            item['report'] = json.loads(row['report_json']) if row['report_json'] else None
            for key in ('elapsed_ms','duplicate_of'):
                if row[key] is not None:
                    item[key] = row[key]
            job['files'].append(item)
        return job

    def key(self, key):
        row = self.connection.execute('SELECT id FROM tasks WHERE idempotency_key=?', (key,)).fetchone()
        return self.get(row[0]) if row else None

    def ensure_capacity(self):
        # Keep all formal reports. Stop admission instead of deleting history.
        allocated = self.connection.execute('PRAGMA page_count').fetchone()[0]*self.connection.execute('PRAGMA page_size').fetchone()[0]
        if allocated > 352*1024**2 or shutil.disk_usage(self.path.parent).free < 512*1024**2:
            raise OverflowError('Task storage reserve reached; back up reports and review retention before retrying')

    def ids(self, active=False, limit=100, offset=0):
        if active:
            return [r[0] for r in self.connection.execute("SELECT id FROM tasks WHERE status IN ('queued','running','cancelling')")]
        return [r[0] for r in self.connection.execute('SELECT id FROM tasks ORDER BY created_at DESC,id LIMIT ? OFFSET ?', (limit,offset))]

    def summaries(self, limit, offset, state='all'):
        jobs = []
        where = " WHERE status IN ('queued','running','cancelling')" if state=='active' else " WHERE status NOT IN ('queued','running','cancelling')" if state=='terminal' else ''
        for row in self.connection.execute('SELECT id,status,created_at,total,finished FROM tasks'+where+' ORDER BY created_at DESC,id LIMIT ? OFFSET ?', (limit,offset)):
            job = dict(row,persistent=True,files=[])
            for item in self.connection.execute("SELECT name,status,size_bytes,json_extract(report_json,'$.verdict') AS verdict FROM task_files WHERE task_id=? ORDER BY ordinal", (row['id'],)):
                job['files'].append(dict(item))
            jobs.append(job)
        return jobs

    def statistics(self):
        fields = ['status','elapsed_ms','report_json IS NOT NULL AS has_report',
                  "json_extract(report_json,'$.sha256') AS sha256","json_extract(report_json,'$.cached') AS cached"]
        for engine in ('sha256','fuzzy','yara_x','clamav','lightgbm'):
            fields.extend([f"json_extract(report_json,'$.engines.{engine}.status') AS {engine}_status",
                           f"json_extract(report_json,'$.engines.{engine}.elapsed_ms') AS {engine}_ms"])
        return dict(task_count=self.connection.execute('SELECT count(*) FROM tasks').fetchone()[0],
                    file_count=self.connection.execute('SELECT count(*) FROM task_files').fetchone()[0],
                    task_statuses=dict(self.connection.execute('SELECT status,count(*) FROM tasks GROUP BY status')),
                    file_statuses=dict(self.connection.execute('SELECT status,count(*) FROM task_files GROUP BY status')),
                    rows=[dict(row) for row in self.connection.execute('SELECT '+','.join(fields)+' FROM task_files ORDER BY rowid DESC LIMIT 500')])

    def close(self):
        if self.connection is not None:
            self.connection.close()
            self.connection = None
        self.owner.close()
