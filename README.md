# Hazee key management trial

Rebuilt from the requirements in the shared conversation. This is new source, not recovered code from that chat.

Python 3.11+. Install `requirements.txt` for HE signature and recovery support. Deploy as a Render **Free Web Service**:

- Build: `pip install -r requirements.txt`
- Start: `python server.py`
- Health check: `/health`
- Set secret `ADMIN_TOKEN` to a random string of at least 24 characters.
- Set `DB_PATH=/tmp/hazee/hazee.sqlite3`.

Open `/` and log in with ADMIN_TOKEN. Create keys with expiration and device limits; key plaintext is displayed only once. Revoke keys from the dashboard. Each verification checks revocation and expiration against the database. Clients must revalidate before allowing a protected operation.

POST `/api/v1/licenses/verify` with JSON `{"key":"HZ-...","device_id":"installation-id"}`. A successful response has `valid: true`, `license_id`, and Unix timestamp `expires_at`. This endpoint does not authorize any third-party NTJR module.

## Trial limitations

SQLite data is ephemeral on Render Free and is lost after restart, redeploy or idle spin-down. JSON export is an inventory, not a restorable database backup. Sessions are in memory. This version is for small tests, not production. Free instances may take about one minute to wake after idle time.

The `he/` directory contains the owner's existing encrypted HE build 16 menu and public release metadata. The patched HE APK trusts the same existing HE signing identity and uses this origin. The simple Hazee Key API remains supported.

To enable HE, set secret environment variables `HE_SIGNING_SEED` (base64url raw Ed25519 seed from the owner's HE state) and `HE_MENU_MATERIAL` (base64url 64-byte material matching the encrypted menu). Never commit these values or the owner's state database. The server refuses to enable HE with a mismatched signing identity or encrypted menu checksum. The old HE state database is not imported: licenses are created in the current dashboard and use its shared expiration, revocation and device quotas. Premium Key Vault stores keys encrypted at rest and recovery token digests. Recovery does not bypass quotas. HTTP error responses do not expose key material.

HE game installations and the Hazee Key checker have different installation IDs. A one-device key already bound to the checker cannot also authorize the game; create a separate key for HE. An already signed lease can remain valid for at most 120 seconds after a revocation.

The HE menu/native/replay payload is retained from the owner's local HE package. This does not claim all features of newer NTJR builds are present or functional. Native game effects have not been tested on an Android device. Feedback photo upload is not implemented by this backend.

Run validation with `python -m unittest -v`.

Additional private HE fixture tests require `HE_TEST_PRIVATE` pointing to the owner's local validation state; these are skipped without it. No private fixtures are in the repository.
