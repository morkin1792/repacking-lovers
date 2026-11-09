package dev.repack.fixture.common;

import android.app.Activity;
import android.content.Intent;
import android.util.Log;
import android.widget.TextView;
import java.io.FileInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.util.Locale;
import org.json.JSONObject;
import org.json.JSONArray;

/** Import counters and read observations only; this case never redirects file paths. */
public final class NativeFileProbe {
    private static Activity active;
    private static JSONObject nativeConfig;
    private static native String smoke(String source, String retained);
    private static native byte[] readImported(String source, String library);
    private static native String constructorObservation(String library);
    private static JSONObject productionState() throws Exception {
        return new JSONObject((String)Class.forName("dev.repack.shim.NativeIntegrity").getMethod("snapshot").invoke(null));
    }
    private static void publicRun(Activity activity, Intent intent) {
        try {
            active = activity; JSONObject initial = productionState();
            nativeConfig = null;
            if (initial.optBoolean("armed")) {
                nativeConfig = new JSONObject().put("path", initial.getString("original_path"));
                try (InputStream input = activity.getAssets().open("repack/native-public.json")) {
                    ByteArrayOutputStream bytes = new ByteArrayOutputStream(); byte[] buffer = new byte[512];
                    for (int count; (count = input.read(buffer)) != -1;) bytes.write(buffer, 0, count);
                    nativeConfig.put("runtime_probe", new JSONObject(bytes.toString("UTF-8")).optBoolean("runtime_probe"));
                }
            }
            JSONObject event = SigningProbe.base(); event.put("run_id", intent.getStringExtra("run_id"));
            event.put("case_id", intent.getStringExtra("case_id")); event.put("scenario", "native-public");
            // Keep the transport bounded even when both callers have 14 registered import tasks.
            initial.remove("tasks"); emit(event, "public-initial", initial);
            System.loadLibrary("repack_observe");
            for (String library : new String[] {"librepack_io_early.so", "librepack_io_late.so"}) {
                byte[] actual = readImported(activity.getApplicationInfo().sourceDir, library);
                if (actual == null) throw new IllegalStateException("Imported native read failed");
                MessageDigest digest = MessageDigest.getInstance("SHA-256"); StringBuilder hash = new StringBuilder();
                for (byte value : digest.digest(actual)) hash.append(String.format(Locale.ROOT, "%02x", value & 255));
                JSONObject value = new JSONObject(); value.put("sha256", hash.toString()); value.put("bytes", actual.length);
                value.put("constructor", new JSONObject(constructorObservation(library)));
                JSONObject state = productionState(); state.remove("tasks"); value.put("state", state);
                emit(event, "public-read/" + library, value);
                emit(event, "public-runtime/" + library, new JSONObject(activeRuntime()));
            }
            emit(event, "public-complete", new JSONObject().put("complete", true));
        } catch (Throwable error) {
            while (error instanceof java.lang.reflect.InvocationTargetException && error.getCause() != null) error = error.getCause();
            Log.e("REPACK_FIXTURE_DETAIL", "Public native fixture failed", error);
            try {
                JSONObject event = SigningProbe.base(); event.put("run_id", intent.getStringExtra("run_id"));
                event.put("case_id", intent.getStringExtra("case_id")); event.put("scenario", "native-public");
                event.put("query_path", "public-failure"); event.put("event", "failure"); event.put("error_class", error.getClass().getName());
                event.put("response_marker", error.toString()); Log.e("REPACK_FIXTURE", event.toString());
            } catch (Exception serialization) { throw new IllegalStateException(serialization); }
        } finally { active = null; nativeConfig = null; }
    }
    /** Called synchronously by JNI while the full import family remains installed. */
    public static String activeRuntime() throws Exception {
        JSONObject result = new JSONObject();
        if (nativeConfig == null || !nativeConfig.optBoolean("runtime_probe")) return result.put("requested", false).toString();
        result.put("requested", true);
        int id = active.getResources().getIdentifier("repack_runtime_marker", "string", active.getPackageName());
        if (id == 0) throw new IllegalStateException("Runtime resource marker absent");
        result.put("resource", active.getString(id));
        Object probe = Class.forName("dev.repack.fixture.common.LazyPatchProbe").getDeclaredConstructor().newInstance();
        result.put("class_accepts", ((javax.net.ssl.HostnameVerifier)probe).verify("native-fixture.invalid", null));
        result.put("class_unrelated", probe.getClass().getMethod("unrelated").invoke(probe));
        String source = active.getApplicationInfo().sourceDir;
        result.put("zip_asset", zipMarker(source));
        result.put("retained_zip_asset", zipMarker(nativeConfig.getString("path")));
        result.put("fresh_apkassets", freshResource(source, id));
        result.put("retained_apkassets", freshResource(nativeConfig.getString("path"), id));
        result.put("splits", SplitProbe.observe(active));
        android.content.pm.PackageInfo info = active.getPackageManager().getPackageInfo(active.getPackageName(),
            android.content.pm.PackageManager.GET_SIGNING_CERTIFICATES);
        JSONArray signers = new JSONArray();
        for (android.content.pm.Signature signature : info.signingInfo.getApkContentsSigners()) signers.put(SigningProbe.digest(signature));
        result.put("signer_sha256", signers); return result.toString();
    }
    private static String zipMarker(String path) throws Exception {
        try (java.util.zip.ZipFile zip = new java.util.zip.ZipFile(path)) {
            java.util.zip.ZipEntry entry = zip.getEntry("assets/repack-runtime-marker.txt");
            if (entry == null || entry.getSize() > 4096) throw new IllegalStateException("ZIP runtime marker absent/oversized");
            try (InputStream input = zip.getInputStream(entry)) {
                ByteArrayOutputStream bytes = new ByteArrayOutputStream(); byte[] buffer = new byte[512];
                for (int count; (count = input.read(buffer)) != -1;) bytes.write(buffer, 0, count);
                return bytes.toString("UTF-8");
            }
        }
    }
    private static JSONObject freshResource(String path, int id) throws Exception {
        JSONObject result = new JSONObject();
        Class<?> assetsClass = Class.forName("android.content.res.ApkAssets");
        java.lang.reflect.Method load = assetsClass.getDeclaredMethod("loadFromPath", String.class); load.setAccessible(true);
        Object apk = load.invoke(null, path);
        Class<?> builderClass = Class.forName("android.content.res.AssetManager$Builder");
        java.lang.reflect.Constructor<?> constructor = builderClass.getDeclaredConstructor(); constructor.setAccessible(true);
        Object builder = constructor.newInstance();
        java.lang.reflect.Method add = builderClass.getDeclaredMethod("addApkAssets", assetsClass); add.setAccessible(true); add.invoke(builder, apk);
        java.lang.reflect.Method build = builderClass.getDeclaredMethod("build"); build.setAccessible(true);
        android.content.res.AssetManager manager = (android.content.res.AssetManager)build.invoke(builder);
        try {
            android.content.res.Resources fresh = new android.content.res.Resources(manager,
                active.getResources().getDisplayMetrics(), active.getResources().getConfiguration());
            result.put("value", fresh.getString(id));
            result.put("path", assetsClass.getDeclaredMethod("getAssetPath").invoke(apk));
        } finally { manager.close(); assetsClass.getDeclaredMethod("close").invoke(apk); }
        return result;
    }
    private static String digest(File path) throws Exception {
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        try (InputStream input = new FileInputStream(path)) {
            byte[] bytes = new byte[8192];
            for (int count; (count = input.read(bytes)) != -1;) sha.update(bytes, 0, count);
        }
        StringBuilder result = new StringBuilder();
        for (byte value : sha.digest()) result.append(String.format(Locale.ROOT, "%02x", value & 255));
        return result.toString();
    }
    private static JSONObject retain(Activity activity, Intent intent) throws Exception {
        JSONObject metadata;
        try (InputStream input = activity.getAssets().open("repack/native-original.json")) {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream(); byte[] buffer = new byte[4096];
            for (int count; (count = input.read(buffer)) != -1;) bytes.write(buffer, 0, count);
            metadata = new JSONObject(bytes.toString("UTF-8"));
        }
        if (metadata.has("members")) {
            String member = intent.getStringExtra("native_member");
            if (member == null) member = "base";
            JSONArray members = metadata.getJSONArray("members"); JSONObject selected = null;
            for (int index = 0; index < members.length(); index++) {
                JSONObject candidate = members.getJSONObject(index);
                if (member.equals(candidate.getString("member"))) {
                    if (selected != null) throw new IllegalStateException("Duplicate retained member");
                    selected = candidate;
                }
            }
            if (selected == null) throw new IllegalStateException("Retained member absent");
            metadata = new JSONObject(selected.toString());
        }
        String asset = metadata.optString("asset", "repack/native-original.apk");
        if (!asset.startsWith("repack/") || asset.contains("..")) throw new IllegalStateException("Invalid original asset");
        String expected = metadata.getString("sha256");
        if (!expected.matches("[0-9a-f]{64}")) throw new IllegalStateException("Invalid original hash");
        File directory = new File(activity.getFilesDir(), "repack-native-original/" + expected);
        if (!directory.isDirectory() && !directory.mkdirs()) throw new IllegalStateException("Original directory unavailable");
        File original = new File(directory, "base.apk");
        boolean existed = original.isFile();
        if ("corrupt".equals(intent.getStringExtra("retained_control")) && existed) {
            if (!original.setWritable(true, true)) throw new IllegalStateException("Fixture corruption control unavailable");
            try (FileOutputStream output = new FileOutputStream(original)) { output.write(0); }
        }
        boolean valid = original.isFile() && expected.equals(digest(original));
        if (!valid) {
            File temporary = new File(directory, "original.tmp");
            try (InputStream input = activity.getAssets().open(asset);
                 FileOutputStream output = new FileOutputStream(temporary)) {
                byte[] buffer = new byte[8192];
                for (int count; (count = input.read(buffer)) != -1;) output.write(buffer, 0, count);
                output.getFD().sync();
            }
            if (!expected.equals(digest(temporary))) { temporary.delete(); throw new IllegalStateException("Embedded original hash mismatch"); }
            if (!temporary.renameTo(original)) throw new IllegalStateException("Original publication failed");
        }
        if (!original.setReadOnly()) throw new IllegalStateException("Original is not read-only");
        metadata.put("path", original.getCanonicalPath()); metadata.put("bytes", original.length());
        metadata.put("cache_state", valid ? "verified" : existed ? "repaired" : "created");
        return metadata;
    }
    private static String selectedSource(Activity activity, Intent intent) {
        String member = intent.getStringExtra("native_member");
        android.content.pm.ApplicationInfo info = activity.getApplicationInfo();
        if (member == null || "base".equals(member)) return info.sourceDir;
        if (info.splitNames != null && info.splitSourceDirs != null) for (int index = 0; index < info.splitNames.length; index++)
            if (member.equals(info.splitNames[index])) return info.splitSourceDirs[index];
        throw new IllegalStateException("Installed member absent");
    }
    public static void run(Activity activity, Intent intent) {
        if ("native-public".equals(intent.getStringExtra("scenario"))) { publicRun(activity, intent); return; }
        try {
            JSONObject event = SigningProbe.base();
            boolean redirect = "native-integrity".equals(intent.getStringExtra("scenario"));
            event.put("run_id", intent.getStringExtra("run_id")); event.put("case_id", intent.getStringExtra("case_id") == null ? redirect ? "T-B01" : "T-B00" : intent.getStringExtra("case_id"));
            event.put("scenario", redirect ? "native-integrity" : "native-smoke"); event.put("query_path", "import-map");
            JSONObject retained = redirect ? retain(activity, intent) : null;
            active = activity; nativeConfig = retained;
            String source = selectedSource(activity, intent);
            long hash = 0xcbf29ce484222325L, size = 0; MessageDigest sha = MessageDigest.getInstance("SHA-256");
            try (FileInputStream input = new FileInputStream(source)) {
                byte[] buffer = new byte[8192];
                for (int count; (count = input.read(buffer)) != -1;) {
                    size += count; sha.update(buffer, 0, count);
                    for (int n = 0; n < count; n++) hash = (hash ^ (buffer[n] & 255)) * 0x100000001b3L;
                }
            }
            System.loadLibrary("repack_hook_smoke");
            JSONObject result = new JSONObject(smoke(source, retained == null ? null : retained.getString("path")));
            if (retained != null) {
                if (!retained.getString("sha256").equals(digest(new File(retained.getString("path")))))
                    throw new IllegalStateException("Native read changed retained original");
                result.put("retained", retained);
            }
            result.put("java_size", size); result.put("java_fnv64", String.format(Locale.ROOT, "%016x", hash));
            result.put("java_source_dir", source);
            StringBuilder digest = new StringBuilder();
            for (byte value : sha.digest()) digest.append(String.format(Locale.ROOT, "%02x", value & 255));
            result.put("java_sha256", digest.toString());
            JSONArray stages = result.optJSONArray("stages"), tasks = result.optJSONArray("tasks");
            JSONObject runtime = result.optJSONObject("active_runtime"), runtimeLate = result.optJSONObject("runtime_after_delayed_load");
            result.remove("stages"); result.remove("tasks");
            result.remove("active_runtime"); result.remove("runtime_after_delayed_load");
            if (stages != null) for (int index = 0; index < stages.length(); index++) {
                JSONObject stage = stages.getJSONObject(index); JSONArray rows = stage.getJSONArray("rows");
                stage.remove("rows"); emit(event, "stage/" + index + "/counters", stage);
                for (int row = 0; row < rows.length(); row++) {
                    JSONObject value = rows.getJSONObject(row);
                    emit(event, "stage/" + index + "/" + value.getString("path"), value);
                }
            }
            if (tasks != null) for (String library : new String[] {"early", "late"}) {
                JSONArray selected = new JSONArray();
                for (int index = 0; index < tasks.length(); index++) {
                    JSONObject task = tasks.getJSONObject(index);
                    if (library.equals(task.getString("library"))) selected.put(task);
                }
                emit(event, "tasks/" + library, new JSONObject().put("tasks", selected));
            }
            if (runtime != null) emit(event, "runtime/early", runtime);
            if (runtimeLate != null) emit(event, "runtime/late", runtimeLate);
            emit(event, "summary", result);
            TextView text = new TextView(activity); text.setText("Native import smoke complete"); activity.setContentView(text);
        } catch (Throwable error) {
            while (error instanceof java.lang.reflect.InvocationTargetException && error.getCause() != null) error = error.getCause();
            Log.e("REPACK_FIXTURE_DETAIL", "Native fixture failed", error);
            try {
                JSONObject event = SigningProbe.base(); event.put("run_id", intent.getStringExtra("run_id"));
                boolean redirect = "native-integrity".equals(intent.getStringExtra("scenario"));
                event.put("case_id", intent.getStringExtra("case_id") == null ? redirect ? "T-B01" : "T-B00" : intent.getStringExtra("case_id")); event.put("scenario", redirect ? "native-integrity" : "native-smoke"); event.put("query_path", "import-map");
                event.put("event", "failure"); event.put("error_class", error.getClass().getName());
                event.put("response_marker", error.toString()); Log.e("REPACK_FIXTURE", event.toString());
            } catch (Exception serialization) { throw new IllegalStateException(serialization); }
        } finally { active = null; nativeConfig = null; }
    }
    private static void emit(JSONObject event, String path, JSONObject value) throws Exception {
        event.put("event", "response"); event.put("query_path", path); event.put("response_marker", value.toString());
        String line = event.toString();
        if (line.getBytes("UTF-8").length > 3500) throw new IllegalStateException("Native observation exceeds log transport budget");
        Log.i("REPACK_FIXTURE", line);
    }
    private NativeFileProbe() {}
}
