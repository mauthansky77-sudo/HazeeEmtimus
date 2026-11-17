package vn.hazee.keycheck;

import android.app.Activity;
import android.content.SharedPreferences;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.text.InputType;
import android.view.Gravity;
import android.view.View;
import android.view.WindowManager;
import android.view.inputmethod.InputMethodManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.TextView;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class MainActivity extends Activity {
    private static final int BG = Color.rgb(16, 23, 37);
    private static final int CARD = Color.rgb(26, 37, 56);
    private static final int WHITE = Color.rgb(233, 237, 245);
    private static final int MUTED = Color.rgb(182, 195, 215);
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private EditText keyInput;
    private TextView resultTitle, resultBody;
    private Button checkButton;
    private ProgressBar progress;
    private String installationId;
    private boolean checking;

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        getWindow().setStatusBarColor(BG);
        getWindow().setNavigationBarColor(BG);
        getWindow().setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE);
        SharedPreferences prefs = getSharedPreferences("hazee_key", MODE_PRIVATE);
        installationId = prefs.getString("installation_id", "");
        if (installationId.isEmpty()) {
            installationId = UUID.randomUUID().toString();
            prefs.edit().putString("installation_id", installationId).apply();
        }
        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.setBackgroundColor(BG);
        LinearLayout page = new LinearLayout(this);
        page.setOrientation(LinearLayout.VERTICAL);
        page.setPadding(dp(24), dp(28), dp(24), dp(24));
        scroll.addView(page);
        setContentView(scroll);
        scroll.setOnApplyWindowInsetsListener((view, insets) -> {
            view.setPadding(insets.getSystemWindowInsetLeft(), insets.getSystemWindowInsetTop(), insets.getSystemWindowInsetRight(), insets.getSystemWindowInsetBottom());
            return insets.consumeSystemWindowInsets();
        });
        scroll.requestApplyInsets();

        TextView badge = text("H", 30, WHITE);
        badge.setTypeface(null, Typeface.BOLD);
        badge.setGravity(Gravity.CENTER);
        badge.setBackground(box(Color.rgb(65,105,225), 18));
        page.addView(badge, new LinearLayout.LayoutParams(dp(64), dp(64)));
        addText(page, "HAZEE KEY", 12, Color.rgb(157, 182, 255), 24).setLetterSpacing(0.16f);
        TextView heading = addText(page, "Kiểm tra key\ncủa bạn", 32, WHITE, 10);
        heading.setTypeface(null, Typeface.BOLD);
        addText(page, "Nhập key do người quản trị Hazee cấp để xem hiệu lực và ngày hết hạn.", 16, MUTED, 12);

        LinearLayout form = card(page, 28);
        addText(form, "KEY HAZEE", 12, MUTED, 0).setTypeface(null, Typeface.BOLD);
        keyInput = new EditText(this);
        keyInput.setHint("HZ-…");
        keyInput.setHintTextColor(MUTED);
        keyInput.setTextColor(WHITE);
        keyInput.setTextSize(17);
        keyInput.setSingleLine(true);
        keyInput.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS | InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD);
        if (android.os.Build.VERSION.SDK_INT >= 26) keyInput.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO);
        keyInput.setSaveEnabled(false);
        keyInput.setPadding(dp(14), dp(14), dp(14), dp(14));
        keyInput.setBackground(box(BG, 10));
        LinearLayout.LayoutParams fieldParams = new LinearLayout.LayoutParams(-1, dp(56));
        fieldParams.topMargin = dp(12);
        form.addView(keyInput, fieldParams);
        checkButton = new Button(this);
        checkButton.setText("Kiểm tra key");
        checkButton.setAllCaps(false);
        checkButton.setTextColor(WHITE);
        checkButton.setTextSize(16);
        checkButton.setBackground(box(Color.rgb(65,105,225), 10));
        LinearLayout.LayoutParams buttonParams = new LinearLayout.LayoutParams(-1, dp(54));
        buttonParams.topMargin = dp(16);
        form.addView(checkButton, buttonParams);
        checkButton.setOnClickListener(v -> check());
        progress = new ProgressBar(this);
        progress.setVisibility(View.GONE);
        LinearLayout.LayoutParams progressParams = new LinearLayout.LayoutParams(dp(28), dp(28));
        progressParams.gravity = Gravity.CENTER;
        progressParams.topMargin = dp(16);
        form.addView(progress, progressParams);

        LinearLayout result = card(page, 16);
        resultTitle = addText(result, "Sẵn sàng kiểm tra", 18, WHITE, 0);
        resultTitle.setTypeface(null, Typeface.BOLD);
        resultTitle.setAccessibilityLiveRegion(View.ACCESSIBILITY_LIVE_REGION_POLITE);
        resultBody = addText(result, "Kết quả sẽ xuất hiện ở đây.", 14, MUTED, 8);
        addText(page, "Máy chủ: hazee-key-trial.onrender.com", 12, MUTED, 24);
        addText(page, "Máy chủ miễn phí có thể cần khoảng một phút để khởi động. Gỡ ứng dụng hoặc xóa dữ liệu sẽ tạo mã cài đặt mới và có thể chiếm thêm một thiết bị của key.", 12, MUTED, 8);
        addText(page, "Ứng dụng chỉ kiểm tra key Hazee. Key này chưa mở menu NTJR hoặc chức năng game.", 12, MUTED, 12);
    }

    private void check() {
        if (checking) return;
        String key = keyInput.getText().toString().trim();
        if (key.isEmpty() || key.length() > 200) {
            keyInput.setError("Nhập key Hazee hợp lệ");
            keyInput.requestFocus();
            return;
        }
        ((InputMethodManager)getSystemService(INPUT_METHOD_SERVICE)).hideSoftInputFromWindow(keyInput.getWindowToken(), 0);
        checking = true;
        checkButton.setEnabled(false);
        keyInput.setEnabled(false);
        checkButton.setText("Đang kiểm tra…");
        progress.setVisibility(View.VISIBLE);
        resultTitle.setText("Đang kết nối máy chủ");
        resultTitle.setTextColor(WHITE);
        resultBody.setText("Vui lòng chờ. Máy chủ có thể đang khởi động.");
        worker.execute(() -> {
            try {
                KeyApi.Result result = KeyApi.verify(key, installationId);
                runOnUiThread(() -> {
                    if (isFinishing() || isDestroyed()) return;
                    finishCheck();
                    resultTitle.setText(result.valid ? "Key hợp lệ" : "Chưa xác minh được key");
                    resultTitle.setTextColor(result.valid ? Color.rgb(110, 224, 180) : Color.rgb(255, 195, 120));
                    if (result.valid) {
                        String expiry = new SimpleDateFormat("dd/MM/yyyy HH:mm z", new Locale("vi", "VN")).format(new Date(result.expiresAt * 1000L));
                        resultBody.setText("Hết hạn: " + expiry + "\nĐã ghi nhận mã cài đặt này trong giới hạn thiết bị của key.");
                    } else resultBody.setText(result.message);
                });
            } catch (Exception error) {
                runOnUiThread(() -> {
                    if (isFinishing() || isDestroyed()) return;
                    finishCheck();
                    resultTitle.setText("Chưa kết nối được");
                    resultTitle.setTextColor(Color.rgb(255, 195, 120));
                    resultBody.setText("Kiểm tra Internet rồi thử lại. Nếu máy chủ đang ngủ, đợi khoảng một phút. Lỗi kết nối không có nghĩa là key đã bị thu hồi.");
                });
            }
        });
    }
    private void finishCheck() {
        checking = false;
        checkButton.setEnabled(true);
        keyInput.setEnabled(true);
        checkButton.setText("Kiểm tra key");
        progress.setVisibility(View.GONE);
    }
    @Override protected void onDestroy() { worker.shutdownNow(); super.onDestroy(); }
    private int dp(int value) { return Math.round(value * getResources().getDisplayMetrics().density); }
    private TextView text(String value, int size, int color) {
        TextView view = new TextView(this);
        view.setText(value); view.setTextColor(color); view.setTextSize(size);
        view.setLineSpacing(dp(3), 1f);
        return view;
    }
    private TextView addText(LinearLayout parent, String value, int size, int color, int top) {
        TextView view = text(value, size, color);
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(-1, -2);
        params.topMargin = dp(top);
        parent.addView(view, params);
        return view;
    }
    private GradientDrawable box(int color, int radius) {
        GradientDrawable drawable = new GradientDrawable();
        drawable.setColor(color); drawable.setCornerRadius(dp(radius));
        return drawable;
    }
    private LinearLayout card(LinearLayout parent, int top) {
        LinearLayout view = new LinearLayout(this);
        view.setOrientation(LinearLayout.VERTICAL);
        view.setPadding(dp(20), dp(20), dp(20), dp(20));
        view.setBackground(box(CARD, 16));
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(-1, -2);
        params.topMargin = dp(top); parent.addView(view, params);
        return view;
    }
}
