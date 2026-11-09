package dev.repack.shim;

import android.content.pm.ApplicationInfo;
import android.os.Build;
import android.os.Process;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import org.json.JSONObject;

/** Optional script-mode Gadget. Every extracted byte comes from the signed base APK. */
public final class GadgetLoader {
    private static boolean attempted;
    private static final String OWNER = "repacking-lovers gadget v1\n";
    private static byte[] read(InputStream input, int maximum) throws Exception {
        java.io.ByteArrayOutputStream output = new java.io.ByteArrayOutputStream(); byte[] buffer = new byte[16384];
        for (int count; (count = input.read(buffer)) != -1;) {
            if (output.size() + count > maximum) throw new IllegalStateException("Gadget input exceeds limit");
            output.write(buffer, 0, count);
        }
        return output.toByteArray();
    }
    private static String hash(File file) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256"); byte[] buffer = new byte[16384];
        try (InputStream input = new FileInputStream(file)) { for (int count; (count = input.read(buffer)) != -1;) digest.update(buffer, 0, count); }
        StringBuilder result = new StringBuilder(); for (byte value : digest.digest()) result.append(String.format(java.util.Locale.US, "%02x", value & 255));
        return result.toString();
    }
    private static File publish(File directory, String name, byte[] bytes) throws Exception {
        File output = new File(directory, name); File temporary = File.createTempFile("gadget-", ".tmp", directory);
        try {
            try (FileOutputStream stream = new FileOutputStream(temporary)) { stream.write(bytes); stream.getFD().sync(); }
            if (!temporary.setReadOnly() || !temporary.renameTo(output)) throw new IllegalStateException("Gadget publication failed");
        } finally { if (temporary.exists()) temporary.delete(); }
        return output;
    }
    private static File asset(ZipFile apk, File directory, String name, String expected, int maximum) throws Exception {
        if (!expected.matches("[0-9a-f]{64}")) throw new IllegalStateException("Invalid Gadget asset hash");
        File target = new File(directory, name);
        if (!target.isFile() || !hash(target).equals(expected)) {
            ZipEntry entry = apk.getEntry("assets/repack/gadget/" + name);
            if (entry == null || entry.getSize() <= 0 || entry.getSize() > maximum) throw new IllegalStateException("Gadget asset missing or oversized");
            byte[] bytes;
            try (InputStream input = apk.getInputStream(entry)) { bytes = read(input, maximum); }
            if (bytes.length != entry.getSize()) throw new IllegalStateException("Truncated Gadget asset");
            target = publish(directory, name, bytes);
            if (!hash(target).equals(expected)) throw new IllegalStateException("Gadget asset SHA differs");
        }
        if (!target.setReadOnly()) throw new IllegalStateException("Gadget asset cannot be made read-only");
        return target.getCanonicalFile();
    }
    static synchronized void initialize(ApplicationInfo info) {
        if (!RepackConfig.GADGET_ENABLED || attempted) return;
        attempted = true; JSONObject details = new JSONObject();
        try {
            details.put("capability", "gadget"); details.put("published", false); details.put("mode", "raw-apk-fixture");
            Bootstrap.event("entry", "factory-classloader", details, null);
            if (Build.VERSION.SDK_INT != 30 || info == null || info.uid != Process.myUid()
                    || !"dev.repack.fixture.identity".equals(info.packageName) || !Build.SUPPORTED_ABIS[0].equals("arm64-v8a"))
                throw new UnsupportedOperationException("Gadget mode requires the owned API30 ARM64 fixture");
            File parent = new File(info.dataDir, "code_cache/repack-gadget-v1"); boolean created = parent.mkdirs();
            if (!parent.isDirectory() || !parent.getCanonicalPath().startsWith(new File(info.dataDir).getCanonicalPath() + File.separator))
                throw new IllegalStateException("Gadget private storage unavailable");
            File owner = new File(parent, "owner.txt");
            if (created) publish(parent, "owner.txt", OWNER.getBytes("UTF-8"));
            for (int attempt = 0; !owner.isFile() && attempt < 20; attempt++) android.os.SystemClock.sleep(10);
            try (InputStream input = new FileInputStream(owner)) {
                if (!new String(read(input, 128), "UTF-8").equals(OWNER)) throw new IllegalStateException("Gadget directory ownership differs");
            }
            try (ZipFile apk = new ZipFile(info.sourceDir)) {
                JSONObject config;
                ZipEntry meta = apk.getEntry("assets/repack/gadget/config.json");
                if (meta == null) throw new IllegalStateException("Gadget asset configuration missing");
                try (InputStream input = apk.getInputStream(meta)) { config = new JSONObject(new String(read(input, 4096), "UTF-8")); }
                String identity = config.getString("library_sha256") + config.getString("script_sha256");
                if (!identity.matches("[0-9a-f]{128}")) throw new IllegalStateException("Gadget config hashes malformed");
                File directory = new File(parent, identity); directory.mkdir();
                if (!directory.isDirectory() || parent.getUsableSpace() < 67108864L) throw new IllegalStateException("Gadget storage capacity unavailable");
                File library = asset(apk, directory, "librepack_gadget.so", config.getString("library_sha256"), 52428800);
                File script = asset(apk, directory, "hook.js", config.getString("script_sha256"), 65536);
                JSONObject interaction = new JSONObject(); interaction.put("type", "script"); interaction.put("path", script.getAbsolutePath());
                JSONObject runtime = new JSONObject(); runtime.put("interaction", interaction); runtime.put("runtime", "qjs"); runtime.put("teardown", "minimal");
                publish(directory, "librepack_gadget.config.so", runtime.toString().getBytes("UTF-8"));
                System.loadLibrary("repack_gadget_fixture");
                System.load(library.getAbsolutePath());
                details.put("published", true); details.put("version", config.getString("version")); details.put("listener", false);
                details.put("library_sha256", hash(library)); details.put("script_sha256", hash(script));
                Bootstrap.event("complete", "factory-classloader", details, null);
            }
        } catch (Throwable failure) { Bootstrap.event("failure", "factory-classloader", details, failure); }
    }
    private GadgetLoader() {}
}
