package dev.repack.fixture.common;

import android.content.Context;
import android.content.pm.PackageInfo;

/** This library is present only in the explicitly built JNI fixture variants. */
public final class NativeProbe {
    static { System.loadLibrary("repack_fixture"); }
    public static native PackageInfo query(Context context, String packageName, int flags);
    public static native String abi();
    private NativeProbe() {}
}
