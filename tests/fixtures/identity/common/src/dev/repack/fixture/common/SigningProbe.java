package dev.repack.fixture.common;

import android.app.Activity;
import android.app.Application;
import android.content.Intent;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Process;
import android.util.Log;
import android.widget.TextView;
import java.lang.reflect.InvocationTargetException;
import java.security.MessageDigest;
import java.util.Arrays;
import org.json.JSONArray;
import org.json.JSONObject;
import java.io.InputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;

public final class SigningProbe {
    private SigningProbe() {}

    static JSONObject base() throws Exception {
        JSONObject event = new JSONObject();
        event.put("schema_version", 1);
        event.put("run_id", JSONObject.NULL);
        event.put("case_id", JSONObject.NULL);
        event.put("pid", Process.myPid());
        event.put("process", Application.getProcessName());
        event.put("event", "marker");
        event.put("scenario", JSONObject.NULL);
        event.put("query_path", JSONObject.NULL);
        event.put("package", JSONObject.NULL);
        event.put("flags", JSONObject.NULL);
        event.put("actual_signer_sha256", new JSONArray());
        event.put("expected_signer_sha256", new JSONArray());
        event.put("comparison", "not-run");
        event.put("response_marker", JSONObject.NULL);
        event.put("error_class", JSONObject.NULL);
        return event;
    }

    public static void marker(String name) {
        try {
            JSONObject event = base();
            event.put("response_marker", name);
            Log.i("REPACK_FIXTURE", event.toString());
        } catch (Exception error) {
            throw new IllegalStateException("Fixture marker serialization failed", error);
        }
    }

    public static void earlyFromAsset(Context context) {
        try (InputStream input = context.getAssets().open("repack-fixture-early-query.json")) {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream(); byte[] buffer = new byte[1024];
            for (int count; (count = input.read(buffer)) != -1;) bytes.write(buffer, 0, count);
            JSONObject config = new JSONObject(bytes.toString("UTF-8"));
            JSONObject event = base();
            event.put("run_id", config.getString("run_id")); event.put("case_id", config.getString("case_id"));
            event.put("event", "query"); event.put("scenario", "provider-before-archive");
            event.put("query_path", "direct-current"); event.put("package", context.getPackageName());
            event.put("flags", PackageManager.GET_SIGNING_CERTIFICATES);
            JSONArray expected = config.getJSONArray("expected_signer_sha256");
            PackageInfo info = context.getPackageManager().getPackageInfo(context.getPackageName(), PackageManager.GET_SIGNING_CERTIFICATES);
            Signature[] observed = info.signingInfo.getApkContentsSigners(); String[] actual = new String[observed.length];
            for (int i = 0; i < observed.length; i++) actual[i] = digest(observed[i]);
            Arrays.sort(actual); JSONArray values = new JSONArray(Arrays.asList(actual));
            event.put("actual_signer_sha256", values); event.put("expected_signer_sha256", expected);
            event.put("comparison", values.toString().equals(expected.toString()) ? "passed" : "failed");
            Log.i("REPACK_FIXTURE", event.toString());
        } catch (FileNotFoundException absent) {
            // Other fixture cases have no scheduled early query.
        } catch (Exception error) { throw new IllegalStateException("Early fixture query failed", error); }
    }

    static String digest(Signature signature) throws Exception {
        byte[] bytes = MessageDigest.getInstance("SHA-256").digest(signature.toByteArray());
        StringBuilder output = new StringBuilder();
        for (byte b : bytes) {
            output.append(Character.forDigit((b >>> 4) & 15, 16));
            output.append(Character.forDigit(b & 15, 16));
        }
        return output.toString();
    }

    private static String required(Intent intent, String name) {
        String value = intent.getStringExtra(name);
        if (value == null || value.length() == 0) {
            throw new IllegalArgumentException("Missing intent extra: " + name);
        }
        return value;
    }

    @SuppressWarnings("deprecation")
    public static void run(Activity activity, Intent intent) {
        JSONObject event;
        try {
            event = base();
        } catch (Exception error) {
            throw new IllegalStateException(error);
        }
        try {
            for (String name : new String[] {"run_id", "case_id", "scenario", "query_path"}) {
                event.put(name, required(intent, name));
            }
            String target = required(intent, "query_package");
            String path = required(intent, "query_path");
            if (!Arrays.asList("direct-legacy", "direct-current", "reflect-legacy", "reflect-current", "jni-legacy", "jni-current").contains(path)) {
                throw new IllegalArgumentException("Unknown query path");
            }
            String[] expected = required(intent, "expected_signer_sha256").split(",", -1);
            for (String value : expected) {
                if (!value.matches("[0-9a-f]{64}")) throw new IllegalArgumentException("Invalid expected digest");
            }
            Arrays.sort(expected);
            event.put("expected_signer_sha256", new JSONArray(Arrays.asList(expected)));
            int flags = path.endsWith("legacy") ? PackageManager.GET_SIGNATURES : PackageManager.GET_SIGNING_CERTIFICATES;
            event.put("flags", flags);
            event.put("package", target);
            PackageManager manager = activity.getPackageManager();
            PackageInfo info;
            if (path.startsWith("jni")) info = NativeProbe.query(activity, target, flags);
            else if (path.startsWith("reflect")) {
                try {
                    info = (PackageInfo) PackageManager.class.getMethod("getPackageInfo", String.class, int.class)
                        .invoke(manager, target, flags);
                } catch (InvocationTargetException error) {
                    throw error.getCause();
                }
            } else {
                info = manager.getPackageInfo(target, flags);
            }
            Signature[] signatures = path.endsWith("legacy") ? info.signatures : info.signingInfo.getApkContentsSigners();
            if (signatures == null || signatures.length == 0) throw new IllegalStateException("No observed signers");
            String[] actual = new String[signatures.length];
            for (int i = 0; i < signatures.length; i++) actual[i] = digest(signatures[i]);
            Arrays.sort(actual);
            event.put("event", "query");
            event.put("actual_signer_sha256", new JSONArray(Arrays.asList(actual)));
            event.put("comparison", Arrays.equals(actual, expected) ? "passed" : "failed");
            if ("T-P10".equals(intent.getStringExtra("case_id"))) event.put("response_marker", SplitProbe.observe(activity).toString());
            if (path.startsWith("jni")) {
                JSONObject nativeState = new JSONObject(); nativeState.put("loaded_abi", NativeProbe.abi());
                nativeState.put("process_64_bit", Process.is64Bit());
                event.put("response_marker", nativeState.toString());
            }
            if ("T-A03".equals(intent.getStringExtra("case_id"))) {
                Context context = activity.createPackageContext(activity.getPackageName(), 0);
                android.content.pm.ApplicationInfo canary = context.getPackageManager().getApplicationInfo(activity.getPackageName(), 0);
                JSONObject fields = new JSONObject(); fields.put("package", info.packageName);
                fields.put("version_code", info.getLongVersionCode()); fields.put("uid", info.applicationInfo.uid);
                fields.put("source_dir", info.applicationInfo.sourceDir); fields.put("public_source_dir", info.applicationInfo.publicSourceDir);
                fields.put("context_canary_uid", canary.uid);
                fields.put("context_canary_source_dir", canary.sourceDir);
                event.put("response_marker", fields.toString());
            }
        } catch (Throwable error) {
            try {
                event.put("event", "failure");
                event.put("comparison", "failed");
                event.put("error_class", error.getClass().getName());
            } catch (Exception serializationError) {
                throw new IllegalStateException(serializationError);
            }
        }
        Log.i("REPACK_FIXTURE", event.toString());
        TextView view = new TextView(activity);
        view.setText("Repack fixture\n" + event.toString());
        activity.setContentView(view);
    }
}
