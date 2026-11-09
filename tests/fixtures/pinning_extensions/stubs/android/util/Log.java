package android.util;
public final class Log {
    public static int patches;
    public static int i(String tag, String text) { if ("REPACK_PATCH".equals(tag)) patches++; return 0; }
}
