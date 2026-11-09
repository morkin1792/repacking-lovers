package dev.repack.shim;

import android.os.IBinder;
import android.os.IInterface;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Map;
import org.json.JSONObject;

/** Java service-cache acquisition only. transact() always forwards the original bytes. */
final class PackageBinder {
    private static Map<String, IBinder> cache;
    private static IBinder previous;
    private static boolean hadEntry;
    private static boolean installed;
    static IBinder original;
    static IBinder wrapped;

    @SuppressWarnings("unchecked")
    static void prepare(Object realPackage, final Object packageProxy) throws Exception {
        cache = (Map<String, IBinder>) PlatformAccess.field(Hidden.SERVICE_MANAGER, Hidden.SERVICE_CACHE).get(null);
        hadEntry = cache.containsKey("package"); previous = cache.get("package");
        original = previous != null ? previous : ((IInterface) realPackage).asBinder();
        if (original == null || !Hidden.PACKAGE_INTERFACE.equals(original.getInterfaceDescriptor()))
            throw new IllegalStateException("Unexpected package Binder descriptor");
        final IBinder captured = original;
        wrapped = (IBinder) Proxy.newProxyInstance(IBinder.class.getClassLoader(), new Class<?>[] {IBinder.class}, new InvocationHandler() {
            public Object invoke(Object instance, Method method, Object[] args) throws Throwable {
                if (method.getDeclaringClass() == Object.class) {
                    if (method.getName().equals("equals")) return instance == args[0];
                    if (method.getName().equals("hashCode")) return System.identityHashCode(instance);
                    if (method.getName().equals("toString")) return "RepackPackageBinder";
                }
                if (method.getName().equals("queryLocalInterface") && args != null && args.length == 1
                        && Hidden.PACKAGE_INTERFACE.equals(args[0])) {
                    JSONObject details = new JSONObject(); details.put("operation", "queryLocalInterface");
                    details.put("published", IdentityShim.published); details.put("descriptor_match", true);
                    IdentityShim.event("complete", details, null); return packageProxy;
                }
                return PlatformAccess.invoke(method, captured, args == null ? new Object[0] : args);
            }
        });
    }
    static void publish() throws Exception {
        if (cache.get("package") != previous) throw new IllegalStateException("Package cache changed during setup");
        cache.put("package", wrapped); installed = true;
        if (cache.get("package") != wrapped) throw new IllegalStateException("Package Binder publication failed");
        JSONObject details = new JSONObject(); details.put("operation", "service-cache-publication");
        details.put("published", true); details.put("had_cache_entry", hadEntry);
        IdentityShim.event("complete", details, null);
    }
    static boolean rollback() {
        if (installed && cache.get("package") == wrapped) {
            if (hadEntry) cache.put("package", previous); else cache.remove("package");
        }
        installed = false; wrapped = null; original = null;
        return cache == null || (cache.containsKey("package") == hadEntry && cache.get("package") == previous);
    }
}
