import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import sys
import tempfile
import unittest
import threading
import urllib.request
import urllib.parse

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import server
from he_compat import HECompat, HEError, PUBLIC_KEY, unb64


@unittest.skipUnless(os.environ.get('HE_TEST_PRIVATE'), 'HE private fixture is available only for owner validation')
class HECompatibilityTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Real backup identity is read only for local validation, never committed.
        private = Path(os.environ['HE_TEST_PRIVATE'])
        key = serialization.load_pem_private_key((private / 'server-ed25519.pem').read_bytes(), password=None)
        os.environ['HE_SIGNING_SEED'] = base64.urlsafe_b64encode(key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())).decode()
        release = json.loads((private / 'release.json').read_text())
        os.environ['HE_MENU_MATERIAL'] = release['material']
        cls.old_db = server.DB_PATH
        cls.temp = tempfile.TemporaryDirectory()
        server.DB_PATH = str(Path(cls.temp.name) / 'keys.sqlite3')
        server.initialize()
        cls.he = server.HE
        cls.release = release

    @classmethod
    def tearDownClass(cls):
        server.HE = None
        server.DB_PATH = cls.old_db
        os.environ.pop('HE_SIGNING_SEED', None)
        os.environ.pop('HE_MENU_MATERIAL', None)
        cls.temp.cleanup()

    def setUp(self):
        self.key = 'HZ-aBc_' + secrets.token_urlsafe(24)
        self.identifier = secrets.token_hex(12)
        with server.connect() as db:
            db.execute('INSERT INTO licenses VALUES (?,?,?,?,?,?,?)', (self.identifier, server.digest(self.key), 'HE test', 4102444800, 1, 0, 1))
        self.data = dict(product='ntjr-zsm-android', platform='android', client_build=16,
                         device_id=secrets.token_urlsafe(24), nonce=secrets.token_urlsafe(32),
                         key=self.key, menu_release=self.release['release'], menu_asset=self.release['asset_sha256'])

    def decode(self, envelope, prefix):
        public = Ed25519PublicKey.from_public_bytes(unb64(PUBLIC_KEY))
        public.verify(unb64(envelope['signature']), (prefix + envelope['payload']).encode())
        payload = json.loads(unb64(envelope['payload']))
        self.assertEqual(payload['nonce'], self.data['nonce'])
        self.assertEqual(payload['device_binding'], hashlib.sha256(('android:' + self.data['device_id']).encode()).hexdigest())
        return payload

    def test_signed_manifest_and_license(self):
        manifest = self.decode(self.he.manifest(self.data), 'NTJR-ANDROID-MENU-V1.')
        self.assertEqual(manifest['asset_sha256'], self.release['asset_sha256'])
        self.assertTrue(manifest['download_url'].startswith(self.he.origin + '/api/v1/android/menu/assets/'))
        license = self.decode(self.he.verify(self.data), 'NTJR-LICENSE-V1.')
        self.assertEqual(unb64(license['menu_resource']['material']), unb64(self.release['material']))
        self.assertLessEqual(license['lease_expires_at'], license['issued_at'] + 120)

    def test_http_manifest_asset_and_verification(self):
        http = server.ThreadingHTTPServer(('127.0.0.1', 0), server.Handler)
        thread = threading.Thread(target=http.serve_forever, daemon=True)
        thread.start()
        try:
            root = 'http://127.0.0.1:' + str(http.server_address[1])
            query = urllib.parse.urlencode(self.data)
            with urllib.request.urlopen(root + '/api/v1/android/menu/manifest?' + query) as response:
                manifest = self.decode(json.load(response), 'NTJR-ANDROID-MENU-V1.')
            with urllib.request.urlopen(root + '/api/v1/android/menu/assets/' + manifest['asset_sha256'] + '.bin') as response:
                self.assertEqual(hashlib.sha256(response.read()).hexdigest(), manifest['asset_sha256'])
            request = urllib.request.Request(root + '/api/v1/licenses/verify', data=json.dumps(self.data).encode(), headers={'Content-Type': 'application/json'})
            with urllib.request.urlopen(request) as response:
                self.decode(json.load(response), 'NTJR-LICENSE-V1.')
        finally:
            http.shutdown()
            http.server_close()
            thread.join()

    def test_menu_part_reassembly_and_integrity(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'parts').mkdir()
            blob = self.he.blob_path.read_bytes()
            chunks = [blob[i:i + 524286] for i in range(0, len(blob), 524286)]
            (root / 'release.json').write_text(json.dumps(dict(self.he.release, parts=len(chunks))))
            for i, data in enumerate(chunks):
                (root / 'parts' / f'menu.{i:03d}.bin').write_bytes(data)
            assembled = HECompat(server.connect, server.verify_license, root=root)
            self.assertEqual(assembled.blob_path.read_bytes(), blob)
            assembled.blob_path.unlink()
            (root / 'parts' / 'menu.000.bin').write_bytes(b'corrupt')
            with self.assertRaises(ValueError):
                HECompat(server.connect, server.verify_license, root=root)

    def test_case_sensitive_key_and_shared_device_quota(self):
        self.he.verify(self.data)
        with self.assertRaises(HEError):
            self.he.verify(dict(self.data, key=self.key.upper()))
        with self.assertRaises(HEError) as error:
            self.he.verify(dict(self.data, device_id=secrets.token_urlsafe(24)))
        self.assertEqual(error.exception.code, 'device_mismatch')
        status, result = server.verify_license(self.key, self.data['device_id'])
        self.assertEqual(status, 200)
        self.assertEqual(result['license_id'], self.identifier)

    def test_revoke_and_mismatched_requests(self):
        for field, value in [('nonce', 'short'), ('client_build', 18), ('menu_asset', '0' * 64)]:
            with self.assertRaises(HEError):
                self.he.verify(dict(self.data, **{field: value}))
        with server.connect() as db:
            db.execute('UPDATE licenses SET revoked=1 WHERE id=?', (self.identifier,))
        with self.assertRaises(HEError):
            self.he.verify(self.data)

    def test_vault_encryption_rotation_revocation_and_quota(self):
        saved = self.he.vault('save', self.data)
        with server.connect() as db:
            row = db.execute('SELECT * FROM he_vault WHERE license_id=?', (self.identifier,)).fetchone()
            self.assertNotIn(self.key.encode(), row['ciphertext'])
            self.assertNotEqual(row['token_digest'], saved['save_token'])
        restored = self.he.vault('restore', dict(self.data, save_token=saved['save_token']))
        self.assertEqual(restored['key'], self.key)
        with self.assertRaises(HEError):
            self.he.vault('restore', dict(self.data, device_id=secrets.token_urlsafe(24), save_token=saved['save_token']))
        rotated = self.he.vault('save', self.data)
        with self.assertRaises(HEError):
            self.he.vault('restore', dict(self.data, save_token=saved['save_token']))
        with server.connect() as db:
            db.execute('UPDATE licenses SET revoked=1 WHERE id=?', (self.identifier,))
        with self.assertRaises(HEError):
            self.he.vault('restore', dict(self.data, save_token=rotated['save_token']))
        self.assertTrue(self.he.vault('clear', dict(self.data, save_token=rotated['save_token']))['removed'])


if __name__ == '__main__':
    unittest.main()
