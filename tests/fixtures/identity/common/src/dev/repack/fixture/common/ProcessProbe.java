package dev.repack.fixture.common;

import android.app.Activity;
import android.app.Service;
import android.app.Application;
import android.content.Context;
import android.content.ComponentName;
import android.content.Intent;
import android.content.ServiceConnection;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Binder;
import android.os.IBinder;
import android.os.Process;
import android.util.Log;
import android.widget.TextView;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.json.JSONArray;
import org.json.JSONObject;

public final class ProcessProbe {
    private static final List<ServiceConnection> connections = new ArrayList<>();
    private static final String[] PATHS = {"direct-legacy", "direct-current", "reflect-legacy", "reflect-current", "jni-legacy", "jni-current"};
    private static PackageInfo query(Context context, String target, String path, int flags) throws Throwable {
        if (path.startsWith("jni")) return NativeProbe.query(context, target, flags);
        if (path.startsWith("reflect")) {
            try { return (PackageInfo) PackageManager.class.getMethod("getPackageInfo", String.class, int.class)
                    .invoke(context.getPackageManager(), target, flags); }
            catch (InvocationTargetException error) { throw error.getCause(); }
        }
        return context.getPackageManager().getPackageInfo(target, flags);
    }
    private static void one(Context context, Intent intent, String target, String label, String path) throws Exception {
        JSONObject event = SigningProbe.base();
        event.put("run_id", intent.getStringExtra("run_id")); event.put("case_id", "T-A14");
        event.put("scenario", "process"); event.put("query_path", intent.getStringExtra("process_role") + "/" + label + "/" + path);
        event.put("package", target); int flags = path.endsWith("legacy") ? PackageManager.GET_SIGNATURES : PackageManager.GET_SIGNING_CERTIFICATES;
        event.put("flags", flags);
        JSONObject details = new JSONObject(); details.put("process_uid", Process.myUid());
        details.put("classloader", context.getClassLoader().getClass().getName());
        try {
            PackageInfo info = query(context, target, path, flags);
            Signature[] signatures = path.endsWith("legacy") ? info.signatures : info.signingInfo.getApkContentsSigners();
            String[] digests = new String[signatures.length];
            for (int index = 0; index < digests.length; index++) digests[index] = SigningProbe.digest(signatures[index]);
            Arrays.sort(digests); event.put("actual_signer_sha256", new JSONArray(Arrays.asList(digests)));
            event.put("event", "query"); details.put("package_uid", info.applicationInfo.uid);
            details.put("source_dir", info.applicationInfo.sourceDir); details.put("version_code", info.getLongVersionCode());
            if (path.startsWith("jni")) details.put("loaded_abi", NativeProbe.abi());
            if (label.equals("self") && path.startsWith("direct")) {
                signatures[0] = new Signature("00");
                details.put("caller_mutated_result", true);
            }
            String expected = intent.getStringExtra(label.equals("self") ? "expected_self" : "expected_other");
            if (expected != null) {
                String[] values = expected.split(","); Arrays.sort(values);
                event.put("expected_signer_sha256", new JSONArray(Arrays.asList(values)));
                event.put("comparison", Arrays.equals(values, digests) ? "passed" : "failed");
            }
        } catch (Throwable error) {
            event.put("event", "failure"); event.put("comparison", "failed"); event.put("error_class", error.getClass().getName());
        }
        details.put("x509_factory_calls", CryptoProbe.calls); event.put("response_marker", details.toString());
        Log.i("REPACK_FIXTURE", event.toString());
    }
    static void run(Context context, Intent intent) {
        try {
            for (String path : PATHS) {
                one(context, intent, context.getPackageName(), "self", path);
                one(context, intent, "dev.repack.fixture.other", "other", path);
            }
            one(context, intent, "dev.repack.fixture.missing", "missing", "direct-current");
        } catch (Exception error) { throw new IllegalStateException(error); }
    }
    public static void launch(Activity activity, Intent intent) {
        String role = intent.getStringExtra("process_role");
        if ("main".equals(role)) run(activity, intent);
        else {
            Class<?> service = "remote".equals(role) ? RemoteService.class : "isolated".equals(role) ? IsolatedService.class : null;
            if (service == null) throw new IllegalArgumentException("Unknown process role");
            Intent query = new Intent(activity, service); query.putExtras(intent);
            ServiceConnection connection = new ServiceConnection() {
                public void onServiceConnected(ComponentName component, IBinder binder) { SigningProbe.marker("process-bound-" + component.getClassName()); }
                public void onServiceDisconnected(ComponentName component) {}
            };
            connections.add(connection);
            if (!activity.bindService(query, connection, Context.BIND_AUTO_CREATE)) throw new IllegalStateException("Fixture bind was refused");
        }
        TextView text = new TextView(activity); text.setText("Repack process fixture: " + role); activity.setContentView(text);
    }
    public static final class RemoteService extends Service {
        @Override public IBinder onBind(Intent intent) { run(this, intent); return new Binder(); }
    }
    public static final class IsolatedService extends Service {
        @Override public IBinder onBind(Intent intent) { run(this, intent); return new Binder(); }
    }
    private ProcessProbe() {}
}
