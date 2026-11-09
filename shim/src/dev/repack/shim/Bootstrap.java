package dev.repack.shim;

import android.app.Application;
import android.content.pm.ApplicationInfo;
import android.os.Process;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import org.json.JSONObject;

public final class Bootstrap {
    private static boolean early;
    private static boolean late;
    private static Application application;

    private Bootstrap() {}

    static void event(String event, String phase, JSONObject details, Throwable failure) {
        try {
            JSONObject item = new JSONObject();
            item.put("schema_version", 1);
            item.put("run_id", JSONObject.NULL);
            item.put("case_id", JSONObject.NULL);
            item.put("pid", Process.myPid());
            item.put("process", Application.getProcessName());
            item.put("event", event);
            item.put("phase", phase);
            item.put("access_mode", "none");
            item.put("packaging", "manifest");
            item.put("descriptor", JSONObject.NULL);
            item.put("endpoint", JSONObject.NULL);
            item.put("reference_replaced", false);
            if (details != null && "identity-access".equals(details.optString("capability"))) {
                item.put("access_mode", details.optBoolean("bypass_active") ? "process-local-bypass" : "ordinary-diagnostic");
                item.put("descriptor", details.opt("descriptor") == null ? JSONObject.NULL : details.get("descriptor"));
            }
            if (details != null && "identity".equals(details.optString("capability"))) {
                item.put("access_mode", details.optBoolean("bypass_active") ? "process-local-bypass" : "none");
                item.put("descriptor", details.opt("descriptor") == null ? JSONObject.NULL : details.get("descriptor"));
                item.put("reference_replaced", details.optBoolean("published"));
            }
            if (details != null && "routing".equals(details.optString("capability"))) {
                JSONObject endpoint = new JSONObject();
                endpoint.put("host", RepackConfig.PROXY_HOST);
                endpoint.put("port", RepackConfig.PROXY_PORT);
                item.put("endpoint", endpoint);
                item.put("reference_replaced", details.optBoolean("published"));
            }
            item.put("error_class", failure == null ? JSONObject.NULL : failure.getClass().getName());
            item.put("details", details == null ? new JSONObject() : details);
            Log.i("REPACK_SHIM", item.toString());
        } catch (Exception error) {
            throw new IllegalStateException("Shim event serialization failed", error);
        }
    }

    public static synchronized void initEarly() {
        if (early) return;
        event("entry", "initEarly", null, null);
        if ("public-metadata".equals(RepackConfig.IDENTITY_MODE)) OriginalIdentity.selfTest();
        else if ("identity-deferred".equals(RepackConfig.IDENTITY_MODE)) {
            try { PlatformAccess.enableBypass(); }
            catch (Exception error) { throw new IllegalStateException(error); }
        }
        else if ("identity".equals(RepackConfig.IDENTITY_MODE) || "identity-failure".equals(RepackConfig.IDENTITY_MODE)
                || "identity-archive".equals(RepackConfig.IDENTITY_MODE)) IdentityShim.init();
        else if (!"none".equals(RepackConfig.IDENTITY_MODE)) PlatformAccess.probe();
        early = true;
        event("complete", "initEarly", null, null);
    }

    /** Controlled late-publication experiment, compiled only with an owned fixture mode. */
    public static synchronized JSONObject fixturePublish(android.content.Context context, boolean clear) throws Exception {
        if (!"identity-deferred".equals(RepackConfig.IDENTITY_MODE)
                || !"dev.repack.fixture.identity".equals(context.getPackageName()) || IdentityShim.published)
            throw new IllegalStateException("Not an unpublished owned cache fixture");
        IdentityShim.init(context, clear);
        return fixtureCounters();
    }

    public static JSONObject fixtureCounters() throws Exception {
        if (!"identity-deferred".equals(RepackConfig.IDENTITY_MODE)) throw new IllegalStateException("Not a cache fixture");
        JSONObject result = new JSONObject(); result.put("published", IdentityShim.published);
        result.put("self_queries", IdentityShim.selfQueries); result.put("cache_clear_count", IdentityShim.cacheClears);
        result.put("input_sha256", RepackConfig.ORIGINAL_APK_SHA256); return result;
    }

    public static synchronized void initLate() {
        if (late) return;
        event("entry", "initLate", null, null);
        if (RepackConfig.ROUTE_ENABLED) Route.install("startup");
        if ("identity-archive".equals(RepackConfig.IDENTITY_MODE)) {
            new Handler(Looper.getMainLooper()).post(new Runnable() {
                public void run() { OriginalArchive.run(application); }
            });
        }
        late = true;
        event("complete", "initLate", null, null);
    }

    static void applicationCreated(final Application application) {
        Bootstrap.application = application;
        if (RepackConfig.ROUTE_ENABLED) {
            new Handler(Looper.getMainLooper()).post(new Runnable() {
                public void run() { Route.register(application); }
            });
        }
    }

    static void classLoader(ApplicationInfo info, ClassLoader input, ClassLoader output) {
        try {
            JSONObject details = new JSONObject();
            details.put("source_dir", info.sourceDir);
            details.put("data_dir", info.dataDir);
            details.put("input_class", input.getClass().getName());
            details.put("output_class", output.getClass().getName());
            details.put("output_identity", System.identityHashCode(output));
            event("forward", "initEarly", details, null);
        } catch (Exception error) {
            event("failure", "initEarly", null, error);
            throw new IllegalStateException(error);
        }
    }

    static void nativeClassLoader(ApplicationInfo info) {
        if (RepackConfig.INTEGRITY_ENABLED) NativeIntegrity.initialize(info);
        if (RepackConfig.GADGET_ENABLED) GadgetLoader.initialize(info);
    }
}
