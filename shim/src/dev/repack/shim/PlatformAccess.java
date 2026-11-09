package dev.repack.shim;

import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Build;
import android.os.Process;
import java.lang.reflect.*;
import java.security.MessageDigest;
import java.util.*;
import org.json.JSONArray;
import org.json.JSONObject;

/** Non-publishing, read-only Binder-interface feasibility probe. */
final class PlatformAccess {
    static boolean bypassActive;
    private static int calls;

    static String type(Class<?> type) {
        if (type.isArray()) return type.getName().replace('.', '/');
        if (!type.isPrimitive()) return "L" + type.getName().replace('.', '/') + ";";
        if (type == void.class) return "V";
        if (type == boolean.class) return "Z";
        if (type == byte.class) return "B";
        if (type == char.class) return "C";
        if (type == short.class) return "S";
        if (type == int.class) return "I";
        if (type == long.class) return "J";
        if (type == float.class) return "F";
        return "D";
    }
    static String descriptor(Method method) {
        StringBuilder value = new StringBuilder(type(method.getDeclaringClass())).append("->").append(method.getName()).append('(');
        for (Class<?> parameter : method.getParameterTypes()) value.append(type(parameter));
        return value.append(')').append(type(method.getReturnType())).toString();
    }
    static String digest(Signature signature) throws Exception {
        byte[] bytes = MessageDigest.getInstance("SHA-256").digest(signature.toByteArray());
        StringBuilder result = new StringBuilder();
        for (byte value : bytes) result.append(String.format(Locale.ROOT, "%02x", value & 255));
        return result.toString();
    }
    static void log(String stage, String outcome, JSONObject data, Throwable error) {
        try {
            JSONObject details = data == null ? new JSONObject() : data;
            details.put("capability", "identity-access");
            details.put("probe_stage", stage);
            details.put("outcome", outcome);
            details.put("probe_token", RepackConfig.PROBE_TOKEN);
            details.put("bypass_active", bypassActive);
            Bootstrap.event(error == null ? "forward" : "failure", "initEarly", details, error);
        } catch (Exception failure) { throw new IllegalStateException(failure); }
    }
    static JSONObject data(String key, Object value) throws Exception { return new JSONObject().put(key, value); }
    static Object invoke(Method method, Object receiver, Object... args) throws Exception {
        try { return method.invoke(receiver, args); }
        catch (InvocationTargetException error) {
            Throwable cause = error.getCause();
            if (cause instanceof Exception) throw (Exception) cause;
            if (cause instanceof Error) throw (Error) cause;
            throw new IllegalStateException(cause);
        }
    }
    static void enableBypass() throws Exception {
        Class<?> implementation = Class.forName("org.lsposed.hiddenapibypass.HiddenApiBypass");
        Object result = invoke(implementation.getMethod("addHiddenApiExemptions", String[].class), null,
                               (Object) new String[] {"L"});
        if (!Boolean.TRUE.equals(result)) throw new IllegalStateException("Process-local bypass rejected exemptions");
        bypassActive = true;
        log("bypass", "passed", data("prefixes", new JSONArray().put("L")), null);
    }
    static Field field(String owner, String name) throws Exception {
        Field field = Class.forName(owner).getDeclaredField(name); field.setAccessible(true); return field;
    }
    static void inventoryFields() {
        for (String[] spec : Hidden.FIELDS) {
            try {
                Field field = field(spec[0], spec[1]);
                JSONObject item = data("descriptor", type(field.getDeclaringClass()) + "->" + field.getName() + ":" + type(field.getType()));
                item.put("modifiers", field.getModifiers());
                if (Modifier.isStatic(field.getModifiers())) {
                    Object value = field.get(null);
                    item.put("read", "passed");
                    item.put("value_class", value == null ? JSONObject.NULL : value.getClass().getName());
                    item.put("identity", value == null ? 0 : System.identityHashCode(value));
                } else item.put("read", "not-run-no-instance");
                log("field", "passed", item, null);
            } catch (Exception error) {
                try { log("field", "failed", data("member", spec[0] + "." + spec[1]), error); }
                catch (Exception failure) { throw new IllegalStateException(failure); }
            }
        }
    }
    static Object[] queryArgs(Class<?> flagType, int flags) {
        Object numeric;
        if (flagType == long.class) numeric = Long.valueOf(flags);
        else numeric = Integer.valueOf(flags);
        return new Object[] { RepackConfig.PACKAGE_NAME, numeric, Integer.valueOf(Process.myUid() / 100000) };
    }
    static void contexts(Class<?> threadClass) throws Exception {
        Method current = threadClass.getDeclaredMethod(Hidden.CURRENT_THREAD); current.setAccessible(true);
        Object thread = invoke(current, null);
        log("current-thread", "passed", data("descriptor", descriptor(current)), null);
        int contexts = 0, managers = 0;
        for (String name : Hidden.CONTEXT_FIELDS) {
            try {
                Object context = field(Hidden.ACTIVITY_THREAD, name).get(thread);
                JSONObject item = data("context_field", name);
                item.put("context_present", context != null);
                if (context != null) {
                    contexts++;
                    Object manager = field(Hidden.CONTEXT_IMPL, "mPackageManager").get(context);
                    item.put("cached_manager_present", manager != null);
                    if (manager != null) {
                        managers++;
                        Field pm = field(Hidden.APPLICATION_PM, "mPM"); Object value = pm.get(manager);
                        pm.set(manager, value);
                        if (pm.get(manager) != value) throw new IllegalStateException("Instance-final identical write mismatch");
                        item.put("mPM_modifiers", pm.getModifiers()); item.put("same_reference_write", true);
                    }
                }
                log("reachable-context", "passed", item, null);
            } catch (Exception error) { log("reachable-context", "failed", data("context_field", name), error); }
        }
        JSONObject item = data("known_contexts", contexts); item.put("existing_managers", managers);
        item.put("scope", "Known ActivityThread context fields only; no heap enumeration or manager creation");
        log("context-summary", "passed", item, null);
    }
    static void probe() {
        try {
            if ("identity-access".equals(RepackConfig.IDENTITY_MODE)) enableBypass();
            inventoryFields();
            Class<?> pm = Class.forName(Hidden.PACKAGE_INTERFACE);
            log("discovery", "passed", data("class", pm.getName()), null);
            Method[] members = pm.getDeclaredMethods();
            for (Method member : members) log("enumeration-member", "passed", data("descriptor", descriptor(member)), null);
            log("enumeration", "passed", data("declared_count", members.length), null);
            final Class<?> flagType = Build.VERSION.SDK_INT >= 33 ? long.class : int.class;
            try {
                Method direct = pm.getDeclaredMethod("getPackageInfo", String.class, flagType, int.class);
                log("direct-lookup", "passed", data("descriptor", descriptor(direct)), null);
            } catch (Exception error) { log("direct-lookup", "failed", null, error); }
            Class<?> thread = Class.forName(Hidden.ACTIVITY_THREAD);
            final Field slot = field(Hidden.ACTIVITY_THREAD, Hidden.PM_FIELD);
            Object captured = slot.get(null);
            if (captured == null) {
                Method getter = thread.getDeclaredMethod(Hidden.GET_PM); getter.setAccessible(true);
                captured = invoke(getter, null);
                log("lazy-initialize-real", "passed", data("descriptor", descriptor(getter)), null);
            }
            if (!pm.isInstance(captured)) throw new IllegalStateException("Unexpected real package interface");
            final Object real = captured;
            contexts(thread);
            slot.set(null, real); // identical-value access measurement; never publish the local proxy
            log("same-reference-write", "passed", data("identity", System.identityHashCode(real)), null);
            calls = 0;
            Object proxy = Proxy.newProxyInstance(pm.getClassLoader(), new Class<?>[] { pm }, new InvocationHandler() {
                @Override public Object invoke(Object instance, Method method, Object[] args) throws Throwable {
                    calls++;
                    log("handler-entry", "passed", data("descriptor", descriptor(method)), null);
                    return PlatformAccess.invoke(method, real, args == null ? new Object[0] : args);
                }
            });
            log("generation", "passed", data("class", proxy.getClass().getName()), null);
            Method query = proxy.getClass().getMethod("getPackageInfo", String.class, flagType, int.class);
            PackageInfo info = (PackageInfo) invoke(query, proxy, queryArgs(flagType, PackageManager.GET_SIGNING_CERTIFICATES));
            JSONArray digests = new JSONArray();
            if (info == null || info.signingInfo == null) throw new IllegalStateException("No actual signing metadata");
            List<String> values = new ArrayList<>();
            for (Signature signer : info.signingInfo.getApkContentsSigners()) values.add(digest(signer));
            Collections.sort(values); for (String value : values) digests.put(value);
            JSONObject actual = data("actual_signer_sha256", digests);
            actual.put("package", info.packageName); actual.put("uid", info.applicationInfo.uid);
            actual.put("source_dir", info.applicationInfo.sourceDir);
            log("forwarding", "passed", actual, null);
            Method canary = proxy.getClass().getMethod("getApplicationInfo", String.class, flagType, int.class);
            ApplicationInfo app = (ApplicationInfo) invoke(canary, proxy, queryArgs(flagType, 0));
            if (app == null || app.uid != Process.myUid()) throw new IllegalStateException("ApplicationInfo canary mismatch");
            log("canary", "passed", data("uid", app.uid), null);
            if (slot.get(null) != real) throw new IllegalStateException("Probe replaced a live reference");
            JSONObject done = data("forwarded_calls", calls); done.put("references_replaced", false);
            log("complete", "passed", done, null);
        } catch (Exception error) { log("complete", "failed", null, error); }
        catch (LinkageError error) { log("complete", "failed", null, error); }
    }
}
