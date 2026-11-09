package dev.repack.shim;

/** All non-SDK class/member names used by the current API30 access probe. */
final class Hidden {
    static final String ACTIVITY_THREAD = "android.app.ActivityThread";
    static final String PACKAGE_INTERFACE = "android.content.pm.IPackageManager";
    static final String CONTEXT_IMPL = "android.app.ContextImpl";
    static final String APPLICATION_PM = "android.app.ApplicationPackageManager";
    static final String SERVICE_MANAGER = "android.os.ServiceManager";
    static final String SERVICE_CACHE = "sCache";
    static final String PACKAGE_MANAGER = "android.content.pm.PackageManager";
    static final String ANDROID_PROXY = "android.net.Proxy";
    static final String PM_FIELD = "sPackageManager";
    static final String GET_PM = "getPackageManager";
    static final String CURRENT_THREAD = "currentActivityThread";
    static final String[][] FIELDS = {
        {ACTIVITY_THREAD, PM_FIELD}, {CONTEXT_IMPL, "mPackageManager"}, {APPLICATION_PM, "mPM"},
        {SERVICE_MANAGER, "sCache"}, {PACKAGE_MANAGER, "sPackageInfoCache"}, {APPLICATION_PM, "sPackageInfoCache"},
        {ANDROID_PROXY, "sDefaultProxySelector"}
    };
    static final String[] CONTEXT_FIELDS = {"mSystemContext", "mSystemUiContext"};
    static final String LIST_SLICE = "android.content.pm.ParceledListSlice";
    static final String PROPERTY_CACHE = "android.app.PropertyInvalidatedCache";
    static final String PACKAGE_INFO_CACHE = "sPackageInfoCache";
    private Hidden() {}
}
