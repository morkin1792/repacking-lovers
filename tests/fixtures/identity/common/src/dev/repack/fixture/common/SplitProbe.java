package dev.repack.fixture.common;

import android.content.Context;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import org.json.JSONArray;
import org.json.JSONObject;

public final class SplitProbe {
    public static JSONObject observe(Context context) throws Exception {
        JSONObject value = new JSONObject();
        for (String name : new String[] {"Parent", "Child"}) {
            Object marker = Class.forName("dev.repack.fixture.split.Split" + name).getMethod("marker").invoke(null);
            value.put(name.toLowerCase(java.util.Locale.ROOT), marker);
        }
        try (InputStream input = context.getAssets().open("repack-feature-child.txt")) {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream(); byte[] buffer = new byte[1024];
            for (int count; (count = input.read(buffer)) != -1;) bytes.write(buffer, 0, count);
            value.put("lazy_asset", bytes.toString("UTF-8"));
        }
        int id = context.getResources().getIdentifier("repack_density_value", "string", context.getPackageName());
        if (id == 0) throw new IllegalStateException("Split resource ID missing");
        value.put("density_resource", context.getString(id)); value.put("native_abi", NativeProbe.abi());
        String[] paths = context.getApplicationInfo().splitSourceDirs;
        value.put("split_count", paths == null ? 0 : paths.length); return value;
    }
    private SplitProbe() {}
}
