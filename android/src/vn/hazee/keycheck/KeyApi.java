package vn.hazee.keycheck;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import org.json.JSONObject;

/** One online verification per request. No offline success cache. */
public final class KeyApi {
    public static final String SERVER = "https://hazee-key-trial.onrender.com";

    public static final class Result {
        public final boolean valid;
        public final long expiresAt;
        public final String message;
        Result(boolean valid, long expiresAt, String message) {
            this.valid = valid;
            this.expiresAt = expiresAt;
            this.message = message;
        }
    }

    public static Result verify(String key, String installationId) throws Exception {
        HttpURLConnection connection = (HttpURLConnection) new URL(SERVER + "/api/v1/licenses/verify").openConnection();
        try {
            connection.setRequestMethod("POST");
            connection.setInstanceFollowRedirects(false);
            connection.setConnectTimeout(20000);
            // Render Free may need about a minute to wake up.
            connection.setReadTimeout(100000);
            connection.setRequestProperty("Content-Type", "application/json; charset=utf-8");
            connection.setRequestProperty("Accept", "application/json");
            connection.setDoOutput(true);
            JSONObject request = new JSONObject();
            request.put("key", key);
            request.put("device_id", installationId);
            byte[] body = request.toString().getBytes("UTF-8");
            connection.setFixedLengthStreamingMode(body.length);
            try (OutputStream stream = connection.getOutputStream()) { stream.write(body); }
            int status = connection.getResponseCode();
            InputStream input = status >= 400 ? connection.getErrorStream() : connection.getInputStream();
            if (input == null) throw new IOException("empty_response");
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            try (InputStream stream = input) {
                byte[] chunk = new byte[2048];
                int count;
                while ((count = stream.read(chunk)) != -1) {
                    if (buffer.size() + count > 16384) throw new IOException("response_too_large");
                    buffer.write(chunk, 0, count);
                }
            }
            if (status == 429) return new Result(false, 0, "Bạn kiểm tra quá nhiều lần. Hãy đợi một phút rồi thử lại.");
            if (status >= 500) throw new IOException("server_unavailable");
            JSONObject response = new JSONObject(new String(buffer.toByteArray(), "UTF-8"));
            if (status == 200 && response.optBoolean("valid", false)) {
                long expires = response.optLong("expires_at", 0);
                if (expires <= 0) throw new IOException("invalid_expiration");
                return new Result(true, expires, "Key hợp lệ");
            }
            String error = response.optString("error", "");
            if (error.equals("device_limit")) return new Result(false, 0, "Key đã đạt giới hạn thiết bị. Liên hệ người quản trị để được hỗ trợ.");
            if (error.equals("invalid_expired_or_revoked")) return new Result(false, 0, "Key không tồn tại, đã hết hạn hoặc đã bị thu hồi.");
            return new Result(false, 0, "Không thể xác minh key. Kiểm tra lại key rồi thử lại.");
        } finally {
            connection.disconnect();
        }
    }
    private KeyApi() {}
}
