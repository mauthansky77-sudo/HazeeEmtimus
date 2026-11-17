"""Signed HE build 16 protocol; all licenses use the existing Hazee database."""
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PRODUCT = 'ntjr-zsm-android'
PUBLIC_KEY = 'JAloE8_ncjvadHjep2jTpt4IzDTDHgcECegrBojblsM'
KEY_ID = '557cdc450c4e5b20'


def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b'=').decode('ascii')


def unb64(value):
    return base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))


class HEError(Exception):
    def __init__(self, status, code):
        self.status, self.code = status, code


class HECompat:
    def __init__(self, connect, verify, root=None):
        self.connect, self.check_license = connect, verify
        self.root = Path(root or Path(__file__).parent / 'he')
        self.origin = os.environ.get('HE_ORIGIN', 'https://hazee-key-trial.onrender.com').rstrip('/')
        if self.origin != 'https://hazee-key-trial.onrender.com':
            raise ValueError('Unexpected HE origin')
        seed = unb64(os.environ['HE_SIGNING_SEED'])
        self.signer = Ed25519PrivateKey.from_private_bytes(seed)
        public = self.signer.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        if b64(public) != PUBLIC_KEY:
            raise ValueError('HE signing identity does not match APK')
        self.material = unb64(os.environ['HE_MENU_MATERIAL'])
        if len(self.material) != 64:
            raise ValueError('Invalid menu material')
        self.release = json.loads((self.root / 'release.json').read_text())
        self.blob_path = self.root / 'menu.bin'
        if not self.blob_path.exists():
            count = self.release.get('parts', 0)
            if type(count) is not int or not 1 <= count <= 64:
                raise ValueError('Invalid HE part count')
            chunks = [self.root / 'parts' / f'menu.{i:03d}.bin' for i in range(count)]
            blob = b''.join(path.read_bytes() for path in chunks)
            if len(blob) != self.release['asset_bytes'] or hashlib.sha256(blob).hexdigest() != self.release['asset_sha256']:
                raise ValueError('HE menu parts checksum mismatch')
            self.blob_path.write_bytes(blob)
        if hashlib.sha256(self.blob_path.read_bytes()).hexdigest() != self.release['asset_sha256']:
            raise ValueError('HE menu checksum mismatch')
        self.vault_cipher = AESGCM(hmac.digest(seed, b'HAZEE-KEY-VAULT-V1', 'sha256'))
        with self.connect() as db:
            db.execute('''CREATE TABLE IF NOT EXISTS he_vault(
              device_digest TEXT PRIMARY KEY, token_digest TEXT UNIQUE NOT NULL,
              license_id TEXT NOT NULL REFERENCES licenses(id), ciphertext BLOB NOT NULL,
              saved_at INTEGER NOT NULL)''')

    def identity(self, data, require_platform=True):
        if data.get('product') != PRODUCT or str(data.get('client_build')) != '16':
            raise HEError(400, 'client_mismatch')
        if require_platform and data.get('platform') != 'android':
            raise HEError(403, 'platform_mismatch')
        for field in ('device_id', 'nonce'):
            if not isinstance(data.get(field), str) or not re.fullmatch(r'[A-Za-z0-9_-]{16,128}', data[field]):
                raise HEError(400, 'invalid_request')

    def payload(self, data):
        return dict(schema=1, product=PRODUCT, platform='android', client_build=16,
                    device_binding=hashlib.sha256(('android:' + data['device_id']).encode()).hexdigest(),
                    nonce=data['nonce'], issued_at=int(time.time()))

    def signed(self, purpose, payload, **extra):
        encoded = b64(json.dumps(payload, sort_keys=True, separators=(',', ':')).encode())
        return dict(extra, algorithm='Ed25519', key_id=KEY_ID, payload=encoded,
                    signature=b64(self.signer.sign((purpose + encoded).encode('ascii'))))

    def manifest(self, data):
        self.identity(data, require_platform=False)
        payload = self.payload(data)
        payload.update(kind='android-menu', revision=self.release['revision'], release=self.release['release'],
                       asset_sha256=self.release['asset_sha256'], asset_bytes=self.release['asset_bytes'],
                       expires_at=payload['issued_at'] + 120,
                       download_url=self.origin + '/api/v1/android/menu/assets/' + self.release['asset_sha256'] + '.bin')
        return self.signed('NTJR-ANDROID-MENU-V1.', payload)

    def authorize(self, data):
        self.identity(data)
        if data.get('menu_release') != self.release['release'] or data.get('menu_asset') != self.release['asset_sha256']:
            raise HEError(409, 'release_mismatch')
        status, result = self.check_license(data.get('key'), data['device_id'])
        if status != 200:
            code = 'device_mismatch' if result.get('error') == 'device_limit' else 'invalid_key'
            raise HEError(status, code)
        return result

    def verify(self, data):
        row = self.authorize(data)
        payload = self.payload(data)
        payload.update(license_id=row['license_id'], license_expires_at=row['expires_at'],
                       lease_expires_at=min(row['expires_at'], payload['issued_at'] + 120),
                       revision=self.release['revision'], menu_resource=dict(schema=1,
                       algorithm='AES256CBC-HMACSHA256', release=self.release['release'],
                       asset_sha256=self.release['asset_sha256'], material=b64(self.material)))
        return self.signed('NTJR-LICENSE-V1.', payload, ok=True)

    def vault(self, operation, data):
        self.identity(data)
        if operation == 'save':
            row = self.authorize(data)
            key = data['key']
            token = secrets.token_urlsafe(32)
            nonce = os.urandom(12)
            sealed = nonce + self.vault_cipher.encrypt(nonce, key.encode(), row['license_id'].encode())
            now = int(time.time())
            with self.connect() as db:
                maximum = db.execute('SELECT max_devices FROM licenses WHERE id=?', (row['license_id'],)).fetchone()[0]
                db.execute('''INSERT INTO he_vault VALUES (?,?,?,?,?) ON CONFLICT(device_digest) DO UPDATE SET
                   token_digest=excluded.token_digest, license_id=excluded.license_id,
                   ciphertext=excluded.ciphertext, saved_at=excluded.saved_at''',
                   (hashlib.sha256(data['device_id'].encode()).hexdigest(), hashlib.sha256(token.encode()).hexdigest(),
                    row['license_id'], sealed, now))
            return dict(ok=True, saved=True, save_token=token, key_hint=key[:8] + '…',
                        expires_at=row['expires_at'], max_devices=maximum, saved_at=now)
        token = data.get('save_token')
        if not isinstance(token, str) or not re.fullmatch(r'[A-Za-z0-9_-]{43}', token):
            raise HEError(401, 'invalid_save_token')
        token_digest = hashlib.sha256(token.encode()).hexdigest()
        if operation == 'clear':
            with self.connect() as db:
                changed = db.execute('DELETE FROM he_vault WHERE token_digest=?', (token_digest,)).rowcount
            return dict(ok=True, removed=bool(changed))
        if operation != 'restore':
            raise HEError(404, 'not_found')
        with self.connect() as db:
            row = db.execute('''SELECT v.*,l.revoked,l.expires,l.digest,l.max_devices FROM he_vault v
                 JOIN licenses l ON l.id=v.license_id WHERE token_digest=?''', (token_digest,)).fetchone()
        if not row:
            raise HEError(404, 'not_found')
        if row['revoked'] or row['expires'] <= time.time():
            raise HEError(403, 'license_inactive')
        try:
            sealed = row['ciphertext']
            key = self.vault_cipher.decrypt(sealed[:12], sealed[12:], row['license_id'].encode()).decode()
            if hashlib.sha256(key.encode()).hexdigest() != row['digest']:
                raise ValueError()
        except Exception:
            raise HEError(500, 'vault_corrupted') from None
        result = self.authorize(dict(data, key=key, menu_release=self.release['release'], menu_asset=self.release['asset_sha256']))
        return dict(ok=True, key=key, expires_at=result['expires_at'], max_devices=row['max_devices'])
