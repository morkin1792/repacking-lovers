package dev.repack.fixture.common;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.util.Log;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.json.JSONArray;
import org.json.JSONObject;

/** Public PM calls before/after an explicitly deferred, fixture-only publication. */
public final class CacheProbe {
    private static final int CURRENT = PackageManager.GET_SIGNING_CERTIFICATES;
    private static final int LEGACY = PackageManager.GET_SIGNATURES;
    private static JSONObject snapshot(PackageInfo info) throws Exception {
        JSONObject result = new JSONObject();
        result.put("package", info.packageName); result.put("uid", info.applicationInfo.uid);
        result.put("source_dir", info.applicationInfo.sourceDir); result.put("version_code", info.getLongVersionCode());
        Signature[] signatures = info.signingInfo != null ? info.signingInfo.getApkContentsSigners() : info.signatures;
        String[] digests = new String[signatures == null ? 0 : signatures.length];
        for (int i = 0; i < digests.length; i++) digests[i] = SigningProbe.digest(signatures[i]);
        Arrays.sort(digests); result.put("signers", new JSONArray(Arrays.asList(digests))); return result;
    }
    private static JSONObject counters(Class<?> bootstrap) throws Exception {
        return (JSONObject) bootstrap.getMethod("fixtureCounters").invoke(null);
    }
    private static void emit(JSONObject config, String path, JSONObject value, Throwable error) throws Exception {
        JSONObject event = SigningProbe.base();
        event.put("run_id", config.getString("run_id")); event.put("case_id", config.optString("case_id", "T-A11"));
        event.put("scenario", "cache"); event.put("query_path", path);
        event.put("package", "dev.repack.fixture.identity");
        event.put("event", error == null ? "query" : "failure");
        event.put("response_marker", value.toString());
        event.put("error_class", error == null ? JSONObject.NULL : error.getClass().getName());
        Log.i("REPACK_FIXTURE", event.toString());
    }
    public static void fromAsset(Context context) {
        JSONObject config = null;
        try (InputStream input = context.getAssets().open("repack-fixture-cache.json")) {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream(); byte[] buffer = new byte[1024];
            for (int count; (count = input.read(buffer)) != -1;) bytes.write(buffer, 0, count);
            config = new JSONObject(bytes.toString("UTF-8"));
            PackageManager manager = context.getPackageManager(); String self = context.getPackageName();
            Class<?> bootstrap = Class.forName("dev.repack.shim.Bootstrap");
            PackageInfo retained = manager.getPackageInfo(self, CURRENT);
            PackageInfo retainedLegacy = manager.getPackageInfo(self, LEGACY);
            PackageInfo retainedOther = manager.getPackageInfo("dev.repack.fixture.other", CURRENT);
            JSONObject before = new JSONObject(); before.put("current", snapshot(retained));
            before.put("legacy", snapshot(retainedLegacy)); before.put("other", snapshot(retainedOther));
            before.put("repeated_same_object", retained == manager.getPackageInfo(self, CURRENT));
            before.put("counters", counters(bootstrap)); emit(config, "before", before, null);
            JSONObject publication = (JSONObject) bootstrap.getMethod("fixturePublish", Context.class, boolean.class)
                    .invoke(null, context, config.getBoolean("clear"));
            emit(config, "publication", publication, null);
            JSONObject after = new JSONObject();
            after.put("current", snapshot(manager.getPackageInfo(self, CURRENT)));
            after.put("after_first", counters(bootstrap));
            after.put("repeat", snapshot(manager.getPackageInfo(self, CURRENT)));
            after.put("after_repeat", counters(bootstrap));
            after.put("legacy", snapshot(manager.getPackageInfo(self, LEGACY)));
            after.put("other", snapshot(manager.getPackageInfo("dev.repack.fixture.other", CURRENT)));
            after.put("retained", snapshot(retained)); after.put("retained_legacy", snapshot(retainedLegacy));
            after.put("new_flags", snapshot(manager.getPackageInfo(self, CURRENT | LEGACY)));
            after.put("no_flags", snapshot(manager.getPackageInfo(self, 0)));
            Context newContext = context.createPackageContext(self, 0);
            after.put("new_context", snapshot(newContext.getPackageManager().getPackageInfo(self, CURRENT)));
            byte[] certificate = android.util.Base64.decode(config.getString("original_certificate"), android.util.Base64.DEFAULT);
            after.put("existing_manager_predicate", manager.hasSigningCertificate(self, certificate, PackageManager.CERT_INPUT_RAW_X509));
            after.put("new_manager_predicate", newContext.getPackageManager().hasSigningCertificate(self, certificate, PackageManager.CERT_INPUT_RAW_X509));
            after.put("final_counters", counters(bootstrap)); emit(config, "after", after, null);
        } catch (FileNotFoundException absent) {
            // Normal bootstrap fixtures deliberately have no deferred-publication asset.
        } catch (Throwable error) {
            try { if (config != null) emit(config, "failure", new JSONObject(), error); }
            catch (Exception serialization) { throw new IllegalStateException(serialization); }
        }
    }
    public static void state(Activity activity, Intent intent) {
        try {
            JSONObject config = new JSONObject(); config.put("run_id", intent.getStringExtra("run_id"));
            if (intent.hasExtra("case_id")) config.put("case_id", intent.getStringExtra("case_id"));
            String write = intent.getStringExtra("sentinel_write");
            if (write != null && !activity.getSharedPreferences("cache-fixture", 0).edit().putString("sentinel", write).commit())
                throw new IllegalStateException("Sentinel write failed");
            JSONObject value = snapshot(activity.getPackageManager().getPackageInfo(activity.getPackageName(), CURRENT));
            value.put("sentinel", activity.getSharedPreferences("cache-fixture", 0).getString("sentinel", "absent"));
            try {
                Class<?> configClass = Class.forName("dev.repack.shim.RepackConfig");
                java.lang.reflect.Field hash = configClass.getDeclaredField("ORIGINAL_APK_SHA256"); hash.setAccessible(true);
                value.put("input_sha256", hash.get(null));
            } catch (ClassNotFoundException genuine) { value.put("input_sha256", JSONObject.NULL); }
            String legacy = activity.getPackageManager().getInstallerPackageName(activity.getPackageName());
            value.put("installer_legacy", legacy == null ? JSONObject.NULL : legacy);
            if (android.os.Build.VERSION.SDK_INT >= 30) {
                android.content.pm.InstallSourceInfo source = activity.getPackageManager().getInstallSourceInfo(activity.getPackageName());
                value.put("installer_installing", source.getInstallingPackageName() == null ? JSONObject.NULL : source.getInstallingPackageName());
                value.put("installer_initiating", source.getInitiatingPackageName() == null ? JSONObject.NULL : source.getInitiatingPackageName());
                value.put("installer_originating", source.getOriginatingPackageName() == null ? JSONObject.NULL : source.getOriginatingPackageName());
            }
            emit(config, "state", value, null);
        } catch (Exception error) { throw new IllegalStateException(error); }
    }
}
