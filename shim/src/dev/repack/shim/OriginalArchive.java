package dev.repack.shim;

import android.app.Application;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.Locale;
import org.json.JSONObject;

/** Post-context archive experiment. No installed sourceDir reads are redirected. */
final class OriginalArchive {
    static String hash(File file) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256"); byte[] buffer = new byte[16384];
        try (InputStream input = new FileInputStream(file)) {
            for (int count; (count = input.read(buffer)) != -1;) digest.update(buffer, 0, count);
        }
        StringBuilder value = new StringBuilder();
        for (byte item : digest.digest()) value.append(String.format(Locale.ROOT, "%02x", item & 255));
        return value.toString();
    }
    static void event(String event, JSONObject details, Throwable error) {
        try {
            details.put("capability", "original-archive"); details.put("probe_token", RepackConfig.PROBE_TOKEN);
            details.put("bypass_active", PlatformAccess.bypassActive); details.put("installed_source_redirected", false);
            Bootstrap.event(event, "context", details, error);
        } catch (Exception failure) { throw new IllegalStateException(failure); }
    }
    static void run(Application application) {
        JSONObject details = new JSONObject();
        try {
            if (application == null || application.getBaseContext() == null) throw new IllegalStateException("Application context is not attached");
            details.put("context_attached", true); event("entry", details, null);
            File directory = new File(application.getFilesDir(), "repack-lovers-originals");
            if (!directory.isDirectory() && !directory.mkdirs()) throw new IllegalStateException("Cannot create private original directory");
            File original = new File(directory, RepackConfig.ORIGINAL_APK_SHA256 + ".apk");
            if (!original.exists()) {
                File temporary = File.createTempFile("original-", ".tmp", directory);
                try {
                    try (InputStream input = application.getAssets().open("repack/original.apk");
                         FileOutputStream output = new FileOutputStream(temporary)) {
                        byte[] buffer = new byte[16384];
                        for (int count; (count = input.read(buffer)) != -1;) output.write(buffer, 0, count);
                        output.getFD().sync();
                    }
                    if (!hash(temporary).equals(RepackConfig.ORIGINAL_APK_SHA256)) throw new IllegalStateException("Copied original hash mismatch");
                    if (!temporary.renameTo(original)) throw new IllegalStateException("Cannot publish private original APK");
                } finally { if (temporary.exists() && !temporary.delete()) throw new IllegalStateException("Temporary original cleanup failed"); }
            }
            String digest = hash(original);
            if (!digest.equals(RepackConfig.ORIGINAL_APK_SHA256)) throw new IllegalStateException("Existing private original changed");
            PackageManager manager = application.getPackageManager();
            PackageInfo current = manager.getPackageArchiveInfo(original.getAbsolutePath(), PackageManager.GET_SIGNING_CERTIFICATES);
            PackageInfo legacy = manager.getPackageArchiveInfo(original.getAbsolutePath(), PackageManager.GET_SIGNATURES);
            if (current == null || current.signingInfo == null || legacy == null || legacy.signatures == null) {
                throw new IllegalStateException("Framework archive parser returned no signing metadata");
            }
            details.put("original_sha256", digest); details.put("original_size", original.length());
            details.put("archive_path", original.getAbsolutePath()); details.put("package", current.packageName);
            details.put("current_signer_sha256", OriginalIdentity.digests(current.signingInfo.getApkContentsSigners()));
            details.put("legacy_signer_sha256", OriginalIdentity.digests(legacy.signatures));
            details.put("history_sha256", OriginalIdentity.orderedDigests(current.signingInfo.getSigningCertificateHistory()));
            details.put("installed_source_dir", application.getApplicationInfo().sourceDir);
            details.put("metadata_source", "framework-getPackageArchiveInfo"); details.put("outcome", "passed");
            event("complete", details, null);
        } catch (Exception error) {
            try { details.put("outcome", "failed"); }
            catch (Exception failure) { throw new IllegalStateException(failure); }
            event("failure", details, error);
        }
    }
}
