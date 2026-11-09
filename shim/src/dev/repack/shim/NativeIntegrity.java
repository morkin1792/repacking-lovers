package dev.repack.shim;

import android.content.pm.ApplicationInfo;
import android.os.Build;
import android.os.Process;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import org.json.JSONArray;
import org.json.JSONObject;

/** Explicit caller filtering; only the installed base path's read-only native imports are mapped. */
public final class NativeIntegrity {
    private static boolean attempted;
    private static JSONObject state;
    private static String originalPath, sourcePath;
    private static native String start(String source, String original, String[] callers);
    private static native String nativeSnapshot();
    private static final String OWNER = "repacking-lovers native-base-bytes v1\n";

    private static File original(ApplicationInfo info, JSONObject details) throws Exception {
        File root = new File(new File(info.dataDir, "files"), "repack-integrity-v1");
        boolean created = root.mkdirs();
        if (!root.isDirectory()) throw new IllegalStateException("Original storage directory unavailable");
        File owner = new File(root, "owner.txt");
        if (created) {
            File temporary = File.createTempFile("owner-", ".tmp", root);
            try {
                try (FileOutputStream output = new FileOutputStream(temporary)) { output.write(OWNER.getBytes("UTF-8")); output.getFD().sync(); }
                if (!temporary.renameTo(owner)) throw new IllegalStateException("Original storage owner publication failed");
            } finally { if (temporary.exists()) temporary.delete(); }
        }
        // Another normal app process may have created the directory just before publishing its marker.
        for (int attempt = 0; !owner.isFile() && attempt < 20; attempt++) android.os.SystemClock.sleep(10);
        byte[] marker = new byte[OWNER.length() + 1]; int count;
        try (InputStream input = new FileInputStream(owner)) { count = input.read(marker); }
        if (count != OWNER.length() || !OWNER.equals(new String(marker, 0, count, "UTF-8")))
            throw new IllegalStateException("Original storage namespace is not owned by this module");
        File output = new File(root, RepackConfig.ORIGINAL_APK_SHA256 + ".apk");
        boolean valid = output.isFile() && OriginalArchive.hash(output).equals(RepackConfig.ORIGINAL_APK_SHA256);
        details.put("storage_state", valid ? "verified" : output.exists() ? "repaired" : "created");
        if (!valid) {
            try (ZipFile apk = new ZipFile(info.sourceDir)) {
                ZipEntry entry = apk.getEntry("assets/repack/original.apk");
                if (entry == null || entry.getSize() <= 0 || entry.getSize() > 1073741824L)
                    throw new IllegalStateException("Original asset missing or outside the one-GiB limit");
                if (root.getUsableSpace() < entry.getSize() + 16777216L) throw new IllegalStateException("Insufficient private storage for original");
                File temporary = File.createTempFile("original-", ".tmp", root);
                try {
                    try (InputStream input = apk.getInputStream(entry); FileOutputStream stream = new FileOutputStream(temporary)) {
                        byte[] buffer = new byte[16384]; long copied = 0;
                        for (int length; (length = input.read(buffer)) != -1;) {
                            copied += length;
                            if (copied > entry.getSize()) throw new IllegalStateException("Original asset exceeds declared size");
                            stream.write(buffer, 0, length);
                        }
                        if (copied != entry.getSize()) throw new IllegalStateException("Original asset is truncated");
                        stream.getFD().sync();
                    }
                    if (!OriginalArchive.hash(temporary).equals(RepackConfig.ORIGINAL_APK_SHA256)) throw new IllegalStateException("Original asset hash mismatch");
                    if (!temporary.renameTo(output)) throw new IllegalStateException("Original publication failed");
                } finally { if (temporary.exists()) temporary.delete(); }
            }
        }
        if (!output.setReadOnly()) throw new IllegalStateException("Original cannot be made read-only");
        // Only this marked module's previous hash-named archives are removed after the new one is verified.
        File[] old = root.listFiles();
        if (old != null) for (File file : old) if (!file.equals(output) && file.getName().matches("[0-9a-f]{64}\\.apk") && file.isFile()) {
            if (!file.delete()) details.put("old_original_cleanup", "incomplete");
        }
        return output.getCanonicalFile();
    }

    static synchronized void initialize(ApplicationInfo info) {
        if (!RepackConfig.INTEGRITY_ENABLED || attempted) return;
        attempted = true; JSONObject details = new JSONObject();
        try {
            details.put("capability", "integrity"); details.put("module", "native-base-bytes");
            details.put("probe_token", RepackConfig.PROBE_TOKEN); details.put("early_hook", "factory-classloader");
            details.put("published", false); Bootstrap.event("entry", "initEarly", details, null);
            if (Build.VERSION.SDK_INT != 30 || info == null || Process.myUid() != info.uid || info.sourceDir == null || info.dataDir == null)
                throw new UnsupportedOperationException("Native base-byte mapping requires the tested API30 normal app process");
            if (!RepackConfig.PACKAGE_NAME.equals(info.packageName)) throw new IllegalStateException("Unexpected original package context");
            File retained = original(info, details);
            originalPath = retained.getAbsolutePath(); sourcePath = info.sourceDir;
            JSONArray names = new JSONArray(RepackConfig.INTEGRITY_CALLERS); String[] callers = new String[names.length()];
            if (callers.length < 1 || callers.length > 2) throw new IllegalStateException("Native caller count is invalid");
            for (int index = 0; index < callers.length; index++) {
                callers[index] = names.getString(index);
                if (!callers[index].matches("lib[A-Za-z0-9_.-]+\\.so") || callers[index].length() > 128)
                    throw new IllegalStateException("Native caller name is invalid");
            }
            System.loadLibrary("repack_integrity");
            state = new JSONObject(start(info.sourceDir, retained.getAbsolutePath(), callers));
            if (!state.optBoolean("armed")) throw new IllegalStateException("Native import task registration failed: " + state);
            details.put("published", true); details.put("original_sha256", RepackConfig.ORIGINAL_APK_SHA256);
            details.put("source_dir", info.sourceDir); details.put("original_path", retained.getAbsolutePath());
            details.put("callers", names); details.put("registered_tasks", state.getInt("registered_tasks"));
            details.put("matched_imports", state.getInt("matched_imports")); details.put("pending_tasks", state.getInt("pending_tasks"));
            details.put("pointer_bits", state.getInt("pointer_bits"));
            Bootstrap.event("complete", "initEarly", details, null);
        } catch (Throwable error) {
            try { details.put("published", false); details.put("outcome", "failed"); }
            catch (Exception serialization) { throw new IllegalStateException(serialization); }
            Bootstrap.event("failure", "initEarly", details, error);
        }
    }
    /** Diagnostic for owned validation adapters; this method exposes no endpoint or configuration mutation. */
    public static synchronized String snapshot() {
        try {
            JSONObject value = new JSONObject(state == null ? "{\"armed\":false}" : nativeSnapshot());
            if (originalPath != null) value.put("original_path", originalPath);
            if (sourcePath != null) value.put("source_dir", sourcePath);
            value.put("original_sha256", RepackConfig.ORIGINAL_APK_SHA256);
            return value.toString();
        } catch (Exception error) { throw new IllegalStateException(error); }
    }
    private NativeIntegrity() {}
}
