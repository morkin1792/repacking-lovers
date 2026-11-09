package dev.repack.shim;

import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Parcel;
import android.os.Process;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.util.*;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import org.json.JSONObject;

/** Only exact self getPackageInfo signing requests are transformed in M1a. */
final class PackageHandler implements InvocationHandler {
    private final Object original;
    PackageHandler(Object original) { this.original = original; }

    static JSONObject fields(PackageInfo info) throws Exception {
        JSONObject item = new JSONObject();
        item.put("package", info.packageName); item.put("version_code", info.getLongVersionCode());
        item.put("uid", info.applicationInfo.uid); item.put("source_dir", info.applicationInfo.sourceDir);
        item.put("public_source_dir", info.applicationInfo.publicSourceDir);
        return item;
    }
    static PackageInfo copySigning(PackageInfo installed, long flags) throws Exception {
        Parcel parcel = Parcel.obtain(); PackageInfo copy;
        try {
            installed.writeToParcel(parcel, 0); parcel.setDataPosition(0); copy = PackageInfo.CREATOR.createFromParcel(parcel);
        } finally { parcel.recycle(); }
        if ((flags & PackageManager.GET_SIGNATURES) != 0) copy.signatures = OriginalIdentity.legacySignatures();
        if ((flags & PackageManager.GET_SIGNING_CERTIFICATES) != 0) copy.signingInfo = OriginalIdentity.signingInfo();
        if (!fields(installed).toString().equals(fields(copy).toString())) throw new IllegalStateException("Installed non-signing fields changed");
        return copy;
    }
    private Object real(String name, Class<?>[] types, Object... args) throws Exception {
        Method method = Class.forName(Hidden.PACKAGE_INTERFACE).getMethod(name, types);
        return PlatformAccess.invoke(method, original, args);
    }
    private String uniquePackage(int uid) throws Exception {
        if (uid / 100000 != Process.myUid() / 100000) return null;
        String[] packages = (String[]) real("getPackagesForUid", new Class<?>[] {int.class}, uid);
        return packages != null && packages.length == 1 ? packages[0] : null;
    }
    static boolean certificate(byte[] bytes, int type) throws Exception {
        Signature[] current = OriginalIdentity.signatures();
        if (current.length != 1) return false; // API30 SigningDetails intentionally excludes multiple signers.
        List<Signature> values = new ArrayList<>(Arrays.asList(OriginalIdentity.history())); values.add(current[0]);
        for (Signature signature : values) {
            byte[] expected = signature.toByteArray();
            if (type == PackageManager.CERT_INPUT_SHA256) expected = MessageDigest.getInstance("SHA-256").digest(expected);
            if (MessageDigest.isEqual(expected, bytes)) return true;
        }
        return false;
    }
    private Signature[][] packageSigning(String name) throws Exception {
        if (name.equals(RepackConfig.PACKAGE_NAME)) return new Signature[][] {OriginalIdentity.signatures(), OriginalIdentity.history()};
        PackageInfo info = (PackageInfo) real("getPackageInfo", new Class<?>[] {String.class, int.class, int.class},
                name, PackageManager.GET_SIGNING_CERTIFICATES, Process.myUid() / 100000);
        if (info == null || info.signingInfo == null) return null;
        Signature[] past = info.signingInfo.hasPastSigningCertificates() ? info.signingInfo.getSigningCertificateHistory() : null;
        return new Signature[][] {info.signingInfo.getApkContentsSigners(), past == null ? new Signature[0] : past};
    }
    static boolean exact(Signature[] first, Signature[] second) {
        return first.length == second.length && new HashSet<>(Arrays.asList(first)).equals(new HashSet<>(Arrays.asList(second)));
    }
    private Object comparison(String first, String second, Object fallback) throws Exception {
        if (first == null || second == null || (int) fallback == PackageManager.SIGNATURE_UNKNOWN_PACKAGE) return fallback;
        Signature[][] a = packageSigning(first), b = packageSigning(second);
        if (a == null || b == null) return fallback;
        if (exact(a[0], b[0])) return PackageManager.SIGNATURE_MATCH;
        if (a[1].length > 0 || b[1].length > 0) {
            Signature[] x = a[1].length > 0 ? new Signature[] {a[1][0]} : a[0];
            Signature[] y = b[1].length > 0 ? new Signature[] {b[1][0]} : b[0];
            if (exact(x, y)) return PackageManager.SIGNATURE_MATCH;
        }
        return PackageManager.SIGNATURE_NO_MATCH;
    }
    private static String order(List<?> packages) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        for (Object value : packages) {
            digest.update(((PackageInfo) value).packageName.getBytes(StandardCharsets.UTF_8)); digest.update((byte) '\n');
        }
        StringBuilder text = new StringBuilder(); for (byte value : digest.digest()) text.append(String.format(Locale.ROOT, "%02x", value & 255));
        return text.toString();
    }
    private Object contracts(Method method, Object[] args, Object returned) throws Exception {
        String descriptor = PlatformAccess.descriptor(method); String name = method.getName();
        String owner = "Landroid/content/pm/IPackageManager;->";
        Object result = returned;
        if (descriptor.equals(owner + "hasSigningCertificate(Ljava/lang/String;[BI)Z")
                && RepackConfig.PACKAGE_NAME.equals(args[0]) && args[1] != null && ((int) args[2] == 0 || (int) args[2] == 1)) {
            result = certificate((byte[]) args[1], (int) args[2]);
        } else if (descriptor.equals(owner + "hasUidSigningCertificate(I[BI)Z") && (int) args[0] == Process.myUid()
                && RepackConfig.PACKAGE_NAME.equals(uniquePackage((int) args[0])) && args[1] != null && ((int) args[2] == 0 || (int) args[2] == 1)) {
            result = certificate((byte[]) args[1], (int) args[2]);
        } else if (descriptor.equals(owner + "checkSignatures(Ljava/lang/String;Ljava/lang/String;)I")
                && (RepackConfig.PACKAGE_NAME.equals(args[0]) || RepackConfig.PACKAGE_NAME.equals(args[1]))) {
            result = comparison((String) args[0], (String) args[1], returned);
        } else if (descriptor.equals(owner + "checkUidSignatures(II)I") && ((int) args[0] == Process.myUid() || (int) args[1] == Process.myUid())) {
            result = comparison(uniquePackage((int) args[0]), uniquePackage((int) args[1]), returned);
        } else if (returned != null && (descriptor.equals(owner + "getInstalledPackages(II)Landroid/content/pm/ParceledListSlice;")
                || descriptor.equals(owner + "getPackagesHoldingPermissions([Ljava/lang/String;II)Landroid/content/pm/ParceledListSlice;"))) {
            int offset = name.equals("getInstalledPackages") ? 0 : 1;
            long flags = ((Number) args[offset]).longValue(); int user = (int) args[offset + 1];
            if (user != Process.myUid() / 100000 || (flags & (PackageManager.GET_SIGNATURES | PackageManager.GET_SIGNING_CERTIFICATES)) == 0) return returned;
            Method materialize = returned.getClass().getMethod("getList"); materialize.setAccessible(true);
            List<?> list = (List<?>) PlatformAccess.invoke(materialize, returned);
            List<PackageInfo> copied = new ArrayList<>(); int changed = 0;
            for (Object value : list) {
                PackageInfo info = (PackageInfo) value;
                if (RepackConfig.PACKAGE_NAME.equals(info.packageName)) { copied.add(copySigning(info, flags)); changed++; }
                else copied.add(info);
            }
            if (!order(list).equals(order(copied))) throw new IllegalStateException("List order changed");
            result = Class.forName(Hidden.LIST_SLICE).getConstructor(List.class).newInstance(copied);
            JSONObject details = new JSONObject(); details.put("operation", name); details.put("descriptor", descriptor);
            details.put("published", IdentityShim.published); details.put("self_entries_changed", changed);
            details.put("list_flags", flags);
            details.put("list_order_sha256", order(list)); details.put("list_count", list.size());
            IdentityShim.event("complete", details, null);
            return result;
        } else return returned;
        JSONObject details = new JSONObject(); details.put("operation", name); details.put("descriptor", descriptor);
        details.put("published", IdentityShim.published); details.put("original_result", returned); details.put("result", result);
        IdentityShim.event("complete", details, null); return result;
    }
    @Override public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
        if (method.getDeclaringClass() == Object.class) {
            if (method.getName().equals("equals")) return proxy == args[0];
            if (method.getName().equals("hashCode")) return System.identityHashCode(proxy);
            if (method.getName().equals("toString")) return "RepackPackageManagerProxy";
        }
        if (PlatformAccess.descriptor(method).equals("Landroid/os/IInterface;->asBinder()Landroid/os/IBinder;")
                && PackageBinder.wrapped != null) return PackageBinder.wrapped;
        Object returned = PlatformAccess.invoke(method, original, args == null ? new Object[0] : args);
        if (RepackConfig.CONTRACTS_ENABLED && args != null) returned = contracts(method, args, returned);
        Class<?>[] parameters = method.getParameterTypes();
        boolean exact = method.getName().equals("getPackageInfo") && method.getReturnType() == PackageInfo.class
                && parameters.length == 3 && parameters[0] == String.class
                && (parameters[1] == int.class || parameters[1] == long.class) && parameters[2] == int.class;
        if (!exact || args == null || !RepackConfig.PACKAGE_NAME.equals(args[0])
                || ((Number) args[2]).intValue() != Process.myUid() / 100000 || returned == null) {
            if (method.getName().equals("getApplicationInfo")) {
                JSONObject details = new JSONObject(); details.put("capability", "identity");
                details.put("descriptor", PlatformAccess.descriptor(method)); details.put("published", IdentityShim.published);
                details.put("forwarded", true); IdentityShim.event("forward", details, null);
            }
            return returned;
        }
        long flags = ((Number) args[1]).longValue();
        if ((flags & (PackageManager.GET_SIGNATURES | PackageManager.GET_SIGNING_CERTIFICATES)) == 0) return returned;
        IdentityShim.selfQueries++;
        PackageInfo installed = (PackageInfo) returned;
        PackageInfo copy = copySigning(installed, flags);
        JSONObject before = fields(installed), after = fields(copy);
        if (!before.toString().equals(after.toString())) throw new IllegalStateException("Installed fields changed while copying signing metadata");
        JSONObject details = new JSONObject(); details.put("capability", "identity");
        details.put("descriptor", PlatformAccess.descriptor(method)); details.put("package", args[0]);
        details.put("flags", flags); details.put("user", args[2]); details.put("published", IdentityShim.published);
        details.put("before_fields", before); details.put("after_fields", after);
        IdentityShim.event("complete", details, null);
        return copy;
    }
}
