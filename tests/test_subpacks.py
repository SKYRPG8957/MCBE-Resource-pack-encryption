import json
from pathlib import Path
import tempfile
import unittest
import zipfile

from Crypto.Cipher import AES
from encrypt import EncryptOptions, encrypt_pack


class SubpackEncryptionTests(unittest.TestCase):
    def encrypt(self, files):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        input_zip = root / 'input.zip'
        with zipfile.ZipFile(input_zip, 'w') as archive:
            for name, data in files.items():
                archive.writestr(name, data)
        self.key = 'a' * 32
        self.progress = []
        options = EncryptOptions(input_zip, root, root / 'output.zip',
                                 root / 'output.key', self.key, {'manifest.json'})
        encrypt_pack(options, progress_cb=lambda done, total, phase:
                     self.progress.append((done, total)))
        archive = zipfile.ZipFile(options.output_zip)
        self.addCleanup(archive.close)
        self.assertEqual(self.progress[-1][0], self.progress[-1][1])
        self.assertEqual(len(archive.namelist()), len(set(archive.namelist())))
        return archive

    @staticmethod
    def decrypt(data, key):
        return AES.new(key.encode(), AES.MODE_CFB, iv=key[:16].encode(),
                       segment_size=8).decrypt(data)

    def contents(self, archive, path):
        data = archive.read(path)
        return json.loads(self.decrypt(data[256:], self.key))['content']

    def assert_round_trip(self, archive, root, expected):
        entries = self.contents(archive, root + 'contents.json')
        self.assertEqual({entry['path'] for entry in entries}, set(expected))
        for entry in entries:
            self.assertEqual(self.decrypt(archive.read(root + entry['path']), entry['key']),
                             expected[entry['path']])

    def test_subpack_without_directory_entries(self):
        archive = self.encrypt({'subpacks/low/textures/a.png': b'low texture'})
        self.assert_round_trip(archive, 'subpacks/low/', {'textures/a.png': b'low texture'})
        self.assertEqual(self.contents(archive, 'contents.json'), [])

    def test_mixed_explicit_and_implicit_directories(self):
        archive = self.encrypt({'subpacks/': b'', 'subpacks/low/': b'',
                                'subpacks/low/textures/a.png': b'low',
                                'subpacks/high/textures/a.png': b'high',
                                'textures/root.png': b'root'})
        self.assert_round_trip(archive, 'subpacks/low/', {'textures/a.png': b'low'})
        self.assert_round_trip(archive, 'subpacks/high/', {'textures/a.png': b'high'})
        self.assert_round_trip(archive, '', {'textures/root.png': b'root'})

    def test_explicit_empty_subpack(self):
        archive = self.encrypt({'subpacks/empty/': b''})
        self.assertEqual(self.contents(archive, 'subpacks/empty/contents.json'), [])
        self.assertIn('subpacks/empty/', archive.namelist())

    def test_files_directly_under_subpacks_are_not_discarded(self):
        archive = self.encrypt({'subpacks/readme.txt': b'notes'})
        self.assert_round_trip(archive, '', {'subpacks/readme.txt': b'notes'})


if __name__ == '__main__':
    unittest.main()
