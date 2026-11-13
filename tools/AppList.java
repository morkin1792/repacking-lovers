package dev.repack.tools;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.drawable.Drawable;
import android.os.UserHandle;
import android.os.Looper;
import android.util.Base64;
import java.io.ByteArrayOutputStream;
import java.util.List;
import java.util.ArrayList;

/** Read-only shell metadata query; no APK pulls or helper app installation. */
public final class AppList {
    private static String encode(String s) throws Exception {
        return Base64.encodeToString(s.getBytes("UTF-8"), Base64.NO_WRAP);
    }
    private static String icon(ApplicationInfo app, PackageManager pm) {
        Bitmap bitmap = null;
        try {
            Drawable image = app.loadIcon(pm);
            if (image == null) return "";
            bitmap = Bitmap.createBitmap(64, 64, Bitmap.Config.ARGB_8888);
            Canvas canvas = new Canvas(bitmap);
            image.setBounds(0, 0, 64, 64);
            image.draw(canvas);
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            bitmap.compress(Bitmap.CompressFormat.PNG, 100, bytes);
            return Base64.encodeToString(bytes.toByteArray(), Base64.NO_WRAP);
        } catch (Throwable ignored) { return ""; }
        finally { if (bitmap != null) bitmap.recycle(); }
    }
    public static void main(String[] args) {
        try {
            int user = Integer.parseInt(args[0]);
            if (Looper.myLooper() == null) Looper.prepareMainLooper();
            Class<?> at = Class.forName("android.app.ActivityThread");
            Object thread = at.getMethod("systemMain").invoke(null);
            Context context = (Context) at.getMethod("getSystemContext").invoke(thread);
            Object handle = UserHandle.class.getMethod("of", int.class).invoke(null, user);
            context = (Context) Context.class.getMethod("createContextAsUser", UserHandle.class, int.class)
                .invoke(context, handle, 0);
            PackageManager pm = context.getPackageManager();
            boolean icons = args.length > 1 && "icons".equals(args[1]);
            List<PackageInfo> packages;
            if (icons) {
                packages = new ArrayList<PackageInfo>();
                for (int i = 2; i < args.length; i++) {
                    try { packages.add(pm.getPackageInfo(args[i], 0)); }
                    catch (PackageManager.NameNotFoundException ignored) { }
                }
            } else packages = pm.getInstalledPackages(0);
            int count = 0;
            for (PackageInfo info : packages) {
                ApplicationInfo app = info.applicationInfo;
                if (app == null || (app.flags & ApplicationInfo.FLAG_SYSTEM) != 0) continue;
                String label;
                try { label = String.valueOf(app.loadLabel(pm)); }
                catch (Throwable ignored) { label = app.packageName; }
                System.out.println("REPACK_APP\t" + encode(app.packageName) + "\t" + encode(label)
                    + "\t" + encode(info.versionName == null ? "" : info.versionName)
                    + "\t" + info.getLongVersionCode() + "\t" + (icons ? icon(app, pm) : ""));
                count++;
            }
            System.out.println("REPACK_APPS_DONE\t" + user + "\t" + count);
        } catch (Throwable error) { error.printStackTrace(); System.exit(2); }
        System.exit(0);
    }
}
