import sqlite3
import pytest
from experiments.backup_task_database import backup


def test_backup_includes_committed_wal_and_never_overwrites(tmp_path):
    source, destination = tmp_path/'live.sqlite3',tmp_path/'backup.sqlite3'
    connection = sqlite3.connect(source)
    connection.execute('PRAGMA journal_mode=WAL')
    connection.execute('CREATE TABLE evidence (value TEXT)')
    connection.execute("INSERT INTO evidence VALUES ('committed')")
    connection.commit()
    backup(source,destination)
    copy = sqlite3.connect(destination)
    assert copy.execute('SELECT value FROM evidence').fetchone()[0]=='committed'
    copy.close()
    with pytest.raises(FileExistsError):
        backup(source,destination)
    assert connection.execute('SELECT count(*) FROM evidence').fetchone()[0]==1
    connection.close()
