package dev.repack.shim;

import android.content.Context;
import android.content.ContextWrapper;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;
import org.json.JSONObject;

/** Prepare before publication; restore the touched process-local slots on setup failure. */
final class IdentityShim {
    static boolean published;
    static int selfQueries;
    static int cacheClears;
    static void event(String action, JSONObject details, Throwable error) {
        try {
            details.put("capability", "identity"); details.put("bypass_active", PlatformAccess.bypassActive);
            details.put("probe_token", RepackConfig.PROBE_TOKEN);
            Bootstrap.event(action, action.equals("forward") || details.has("flags") || details.has("operation") ? "query" : "initEarly", details, error);
        } catch (Exception failure) { throw new IllegalStateException(failure); }
    }
    static void init() { init(null, false); }
    static void init(Context supplied, boolean clearCache) {
        Field slot = null; Object original = null;
        List<Object> managers = new ArrayList<>(), prior = new ArrayList<>();
        Field managerSlot = null;
        try {
            PlatformAccess.enableBypass();
            OriginalIdentity.signingInfo(); // Validate metadata before changing any PM reference; no self query.
            slot = PlatformAccess.field(Hidden.ACTIVITY_THREAD, Hidden.PM_FIELD);
            original = slot.get(null);
            Class<?> threadClass = Class.forName(Hidden.ACTIVITY_THREAD);
            Method getter = threadClass.getDeclaredMethod(Hidden.GET_PM); getter.setAccessible(true);
            if (original == null) original = PlatformAccess.invoke(getter, null);
            Class<?> contract = Class.forName(Hidden.PACKAGE_INTERFACE);
            if (!contract.isInstance(original)) throw new IllegalStateException("Unexpected package interface");
            Object proxy = Proxy.newProxyInstance(contract.getClassLoader(), new Class<?>[] { contract }, new PackageHandler(original));
            if (RepackConfig.PACKAGE_BINDER_ENABLED) PackageBinder.prepare(original, proxy);
            Method current = threadClass.getDeclaredMethod(Hidden.CURRENT_THREAD); current.setAccessible(true);
            Object thread = PlatformAccess.invoke(current, null);
            if (supplied != null) {
                Context base = supplied;
                while (base instanceof ContextWrapper) base = ((ContextWrapper) base).getBaseContext();
                Object manager = PlatformAccess.field(Hidden.CONTEXT_IMPL, "mPackageManager").get(base);
                if (manager != null) {
                    managerSlot = PlatformAccess.field(Hidden.APPLICATION_PM, "mPM");
                    managers.add(manager); prior.add(managerSlot.get(manager));
                }
            }
            for (String name : Hidden.CONTEXT_FIELDS) {
                Object context;
                try { context = PlatformAccess.field(Hidden.ACTIVITY_THREAD, name).get(thread); }
                catch (NoSuchFieldException optional) { continue; }
                if (context != null) {
                    Object manager = PlatformAccess.field(Hidden.CONTEXT_IMPL, "mPackageManager").get(context);
                    if (manager != null && !managers.contains(manager)) {
                        if (managerSlot == null) managerSlot = PlatformAccess.field(Hidden.APPLICATION_PM, "mPM");
                        managers.add(manager); prior.add(managerSlot.get(manager));
                    }
                }
            }
            if ("identity-failure".equals(RepackConfig.IDENTITY_MODE) && !RepackConfig.PACKAGE_BINDER_ENABLED)
                throw new IllegalStateException("fixture-before-publication");
            slot.set(null, proxy);
            for (Object manager : managers) managerSlot.set(manager, proxy);
            if (slot.get(null) != proxy) throw new IllegalStateException("Primary publication failed");
            for (Object manager : managers) if (managerSlot.get(manager) != proxy) throw new IllegalStateException("Existing manager publication failed");
            published = true;
            if (RepackConfig.PACKAGE_BINDER_ENABLED) PackageBinder.publish();
            if ("identity-failure".equals(RepackConfig.IDENTITY_MODE))
                throw new IllegalStateException("fixture-after-binder-publication");
            if (clearCache) {
                if (cacheClears != 0) throw new IllegalStateException("Cache already cleared in this process");
                Object cache = PlatformAccess.field(Hidden.PACKAGE_MANAGER, Hidden.PACKAGE_INFO_CACHE).get(null);
                Method clear = Class.forName(Hidden.PROPERTY_CACHE).getDeclaredMethod("clear");
                clear.setAccessible(true); PlatformAccess.invoke(clear, cache); cacheClears++;
            }
            JSONObject details = new JSONObject(); details.put("published", true); details.put("existing_managers", managers.size());
            details.put("cache_clear_count", cacheClears);
            details.put("metadata_source", "embedded-host-verified-certificates");
            details.put("descriptor", "Landroid/app/ActivityThread;->sPackageManager:Landroid/content/pm/IPackageManager;");
            event("complete", details, null);
        } catch (Exception error) {
            boolean restored = true, binderRestored = true;
            try {
                if (RepackConfig.PACKAGE_BINDER_ENABLED) {
                    binderRestored = PackageBinder.rollback(); restored = binderRestored;
                }
                if (slot != null && original != null) slot.set(null, original);
                if (managerSlot != null) for (int i = 0; i < managers.size(); i++) managerSlot.set(managers.get(i), prior.get(i));
                if (slot != null && original != null && slot.get(null) != original) restored = false;
                if (managerSlot != null) for (int i = 0; i < managers.size(); i++) if (managerSlot.get(managers.get(i)) != prior.get(i)) restored = false;
            } catch (Exception rollback) { restored = false; error.addSuppressed(rollback); }
            published = false;
            try {
                JSONObject details = new JSONObject(); details.put("published", false); details.put("rollback_verified", restored);
                details.put("binder_rollback_verified", binderRestored);
                details.put("forced_failure", "identity-failure".equals(RepackConfig.IDENTITY_MODE));
                event("failure", details, error);
            } catch (Exception serialization) { throw new IllegalStateException(serialization); }
        }
    }
}
