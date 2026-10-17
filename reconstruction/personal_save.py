"""Stage native SP saves, retaining backups and refusing concurrent overwrite."""
import hashlib
import base64
import msvcrt
import os
from pathlib import Path


class PersonalSave:
    def __init__(self, folder, source=None):
        self.folder = Path(folder)
        self.source = Path(source) if source else Path(os.environ['APPDATA']) / 'wenilla-rogue/characters.txt'
        self.folder.mkdir(parents=True, exist_ok=True)
        self.lock = (self.folder / 'session.lock').open('a+b')
        self.lock.seek(0)
        try:
            msvcrt.locking(self.lock.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError:
            self.lock.close()
            raise RuntimeError('Your co-op character save is already in use') from None
        try:
            self.original = self.source.read_bytes() if self.source.exists() else None
            self.target = self.folder / 'characters.txt'
            if self.target.exists():
                previous = self.target.read_bytes()
                if previous != self.original:
                    retained = self.folder / ('retained-' + hashlib.sha256(previous).hexdigest() + '.txt')
                    if not retained.exists():
                        retained.write_bytes(previous)
            if self.original is not None:
                self.target.write_bytes(self.original)
            elif self.target.exists():
                # Never silently reuse another previous profile when SP is empty.
                self.target.unlink()
        except Exception:
            self.close()
            raise

    def commit(self):
        if not self.target.exists():
            return
        result = self.target.read_bytes()
        if result == self.original:
            return
        if not 32 <= len(result) <= 4 * 1024 * 1024 or not result.startswith(b'RSE1:'):
            raise ValueError('Native save was not recognized; retained in the co-op profile')
        if len(base64.b64decode(result[5:], validate=True)) < 28:
            raise ValueError('Native save envelope is incomplete; retained in the co-op profile')
        current = self.source.read_bytes() if self.source.exists() else None
        if current != self.original:
            raise RuntimeError('Single-player save changed during co-op; both saves retained separately')
        self.source.parent.mkdir(parents=True, exist_ok=True)
        if current is not None:
            backup = self.folder / ('sp-backup-' + hashlib.sha256(current).hexdigest() + '.txt')
            if not backup.exists():
                backup.write_bytes(current)
        temporary = self.source.with_name('characters.coop.tmp')
        temporary.write_bytes(result)
        temporary.replace(self.source)
        self.original = result

    def close(self):
        if not self.lock.closed:
            self.lock.seek(0)
            msvcrt.locking(self.lock.fileno(), msvcrt.LK_UNLCK, 1)
            self.lock.close()
