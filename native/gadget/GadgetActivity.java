package dev.repack.fixture.identity;

import android.app.Activity;
import android.os.Bundle;
import android.os.Process;
import android.util.Log;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.FileInputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import org.json.JSONObject;

public final class GadgetActivity extends Activity {
    private static native boolean nativeGate(String source, long expected);
    private static native int nativeUnrelated();
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        android.widget.TextView label = new android.widget.TextView(this);
        label.setText("Repack gadget fixture"); setContentView(label);
        new Thread(() -> {
            JSONObject result = new JSONObject();
            try {
                result.put("token", getIntent().getStringExtra("token"));
                result.put("pid", Process.myPid()); result.put("process", getApplicationInfo().processName);
                result.put("status", "failed");
                String maps;
                try (InputStream stream = new FileInputStream("/proc/self/maps")) { maps = read(stream); }
                boolean present = maps.contains("librepack_gadget.so");
                result.put("gadget_present", present);
                if (present && getIntent().getBooleanExtra("detect_gadget", false)) {
                    result.put("status", "blocked-gadget");
                } else {
                    System.loadLibrary("repack_gadget_fixture");
                    boolean gate = nativeGate(getApplicationInfo().sourceDir, Long.parseUnsignedLong(getIntent().getStringExtra("expected_fnv"), 16));
                    result.put("gate", gate); result.put("unrelated", nativeUnrelated());
                    if (gate) {
                        HttpURLConnection connection = (HttpURLConnection)new URL(getIntent().getStringExtra("url")).openConnection();
                        connection.setConnectTimeout(6000); connection.setReadTimeout(6000);
                        result.put("http_status", connection.getResponseCode());
                        try (InputStream input = connection.getInputStream()) { result.put("body", read(input)); }
                        connection.disconnect(); result.put("status", "response");
                    } else result.put("status", "blocked-integrity");
                }
            } catch (Throwable failure) {
                try { result.put("error_type", failure.getClass().getName()); result.put("error", failure.toString()); }
                catch (Exception ignored) { throw new IllegalStateException(ignored); }
            }
            Log.i("REPACK_GADGET_FIXTURE", result.toString());
        }, "repack-gadget-fixture").start();
    }
    private static String read(InputStream input) throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream(); byte[] buffer = new byte[8192];
        for (int count; (count = input.read(buffer)) != -1;) { output.write(buffer, 0, count); if (output.size() > 1048576) throw new IllegalStateException("Fixture response too large"); }
        return output.toString("UTF-8");
    }
}
