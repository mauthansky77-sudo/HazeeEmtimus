# Hazee key management trial

Rebuilt from the requirements in the shared conversation. This is new source, not recovered code from that chat.

Python 3.11+ standard library; no packages required. Deploy as a Render **Free Web Service**:

- Build: `python -m py_compile server.py`
- Start: `python server.py`
- Health check: `/health`
- Set secret `ADMIN_TOKEN` to a random string of at least 24 characters.
- Set `DB_PATH=/tmp/hazee/hazee.sqlite3`.

Open `/` and log in with ADMIN_TOKEN. Create keys with expiration and device limits; key plaintext is displayed only once. Revoke keys from the dashboard. Each verification checks revocation and expiration against the database. Clients must revalidate before allowing a protected operation.

POST `/api/v1/licenses/verify` with JSON `{"key":"HZ-...","device_id":"installation-id"}`. A successful response has `valid: true`, `license_id`, and Unix timestamp `expires_at`. This endpoint does not authorize any third-party NTJR module.

## Trial limitations

SQLite data is ephemeral on Render Free and is lost after restart, redeploy or idle spin-down. JSON export is an inventory, not a restorable database backup. Sessions are in memory. This version is for small tests, not production. Free instances may take about one minute to wake after idle time.

This source contains no APK, game assets, NTJR bypass, encrypted module, or APK download service. Existing APKs are not connected to this backend. APK client integration and durable database storage remain separate work.

Run validation with `python -m unittest -v`.
