import tempfile
from pathlib import Path
import unittest
import os
from unittest.mock import patch

from personal_save import PersonalSave


class SaveTests(unittest.TestCase):
    def test_disconnect_preserves_native_saved_progress(self):
        from room_client import RoomClient
        from native_probe import ACTIVE_HASH
        client = RoomClient('http://127.0.0.1:47770')
        client.room = dict(id='isolated-save-test', slot=1, players=[1], connection={'port': 47771})
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'analysis').mkdir()
            source = root / 'characters.txt'
            original, earned = b'RSE1:' + b'a' * 60, b'RSE1:' + b'b' * 60
            source.write_bytes(original)
            staged = PersonalSave(root / 'coop', source)
            def disconnected(*args, **kwargs):
                staged.target.write_bytes(earned)
                raise ConnectionError('diagnostic disconnect')
            with patch.dict(os.environ), patch('room_client.ROOT', root), \
                    patch('personal_save.PersonalSave', return_value=staged), \
                    patch.object(client, 'check_compatibility', return_value={'sha256': ACTIVE_HASH}), \
                    patch.object(client, 'poll_room', return_value=True), \
                    patch('native_probe.run', side_effect=disconnected):
                client.play(dict(id='isolated-save-test', slot=1, players=[1], connection={'port': 47771}))
            self.assertIn('diagnostic disconnect', client.error)
            self.assertEqual(source.read_bytes(), earned)
            self.assertTrue(staged.lock.closed)
            self.assertEqual(next(staged.folder.glob('sp-backup-*')).read_bytes(), original)

    def test_native_progress_backup_conflict_and_lock(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / 'sp/characters.txt'
            source.parent.mkdir()
            original = b'RSE1:' + b'a' * 60
            source.write_bytes(original)
            save = PersonalSave(root / 'coop', source)
            try:
                self.assertEqual(save.target.read_bytes(), original)
                with self.assertRaises(RuntimeError):
                    PersonalSave(root / 'coop', source)
                earned = b'RSE1:' + b'b' * 60
                save.target.write_bytes(earned)
                save.commit()
                self.assertEqual(source.read_bytes(), earned)
                self.assertEqual(next((root / 'coop').glob('sp-backup-*')).read_bytes(), original)
                source.write_bytes(original)
                save.target.write_bytes(b'RSE1:' + b'c' * 60)
                with self.assertRaises(RuntimeError):
                    save.commit()
                self.assertEqual(source.read_bytes(), original)
            finally:
                save.close()


if __name__ == '__main__':
    unittest.main()
