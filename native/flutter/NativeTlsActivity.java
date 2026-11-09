package dev.repack.fixture.identity;

import android.app.Activity;
import android.os.Bundle;
import android.os.Process;
import android.util.Log;
import io.flutter.embedding.engine.FlutterEngine;
import io.flutter.embedding.engine.dart.DartExecutor;
import io.flutter.plugin.common.MethodChannel;
import java.util.Arrays;
import org.json.JSONObject;

public final class NativeTlsActivity extends Activity {
    private FlutterEngine engine;
    @Override public void onCreate(Bundle saved) {
        super.onCreate(saved);
        try {
            engine = new FlutterEngine(this);
            new MethodChannel(engine.getDartExecutor().getBinaryMessenger(), "repack.fixture.native")
                .setMethodCallHandler((call, reply) -> {
                    try {
                        JSONObject result = new JSONObject((String) call.arguments);
                        result.put("pid", Process.myPid());
                        result.put("process", getApplicationInfo().processName);
                        Log.i("REPACK_NATIVE", result.toString());
                        reply.success(null);
                    } catch (Exception error) { reply.error("fixture", error.toString(), null); }
                });
            engine.getDartExecutor().executeDartEntrypoint(DartExecutor.DartEntrypoint.createDefault(),
                Arrays.asList(getIntent().getStringExtra("token"), getIntent().getStringExtra("url")));
        } catch (Throwable error) {
            Log.e("REPACK_NATIVE", "startup failed", error);
        }
    }
    @Override public void onDestroy() { if (engine != null) engine.destroy(); super.onDestroy(); }
}
