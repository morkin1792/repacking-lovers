package dev.repack.fixture.common;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import android.os.Process;
import android.util.Log;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Arrays;
import org.json.JSONArray;
import org.json.JSONObject;

/** Exact API30 fixture transactions; no transaction-code emulation in the shim. */
public final class BinderProbe {
    private static final String DESCRIPTOR = "android.content.pm.IPackageManager";
    private static JSONObject config;
    private static Object asInterface(IBinder binder) throws Exception {
        return Class.forName(DESCRIPTOR + "$Stub").getDeclaredMethod("asInterface", IBinder.class).invoke(null, binder);
    }
    private static PackageInfo query(Object stub, String target, int flags) throws Exception {
        return (PackageInfo) Class.forName(DESCRIPTOR).getMethod("getPackageInfo", String.class, int.class, int.class)
                .invoke(stub, target, flags, Process.myUid() / 100000);
    }
    private static PackageInfo transact(IBinder binder, String target, int flags) throws Exception {
        Field field = Class.forName(DESCRIPTOR + "$Stub").getDeclaredField("TRANSACTION_getPackageInfo"); field.setAccessible(true);
        Parcel request = Parcel.obtain(), response = Parcel.obtain();
        try {
            request.writeInterfaceToken(DESCRIPTOR); request.writeString(target); request.writeInt(flags);
            request.writeInt(Process.myUid() / 100000);
            if (!binder.transact(field.getInt(null), request, response, 0)) throw new IllegalStateException("Real package transaction was rejected");
            response.readException(); return response.readInt() != 0 ? PackageInfo.CREATOR.createFromParcel(response) : null;
        } finally { request.recycle(); response.recycle(); }
    }
    private static JSONObject info(PackageInfo info, int flags) throws Exception {
        JSONObject value = new JSONObject(); value.put("null_result", info == null);
        if (info == null) return value;
        Signature[] signatures = flags == PackageManager.GET_SIGNATURES ? info.signatures : info.signingInfo.getApkContentsSigners();
        String[] digests = new String[signatures.length];
        for (int i = 0; i < signatures.length; i++) digests[i] = SigningProbe.digest(signatures[i]);
        Arrays.sort(digests); value.put("signers", new JSONArray(Arrays.asList(digests)));
        value.put("uid", info.applicationInfo.uid); value.put("source_dir", info.applicationInfo.sourceDir);
        value.put("version_code", info.getLongVersionCode()); return value;
    }
    private static void emit(String path, String target, int flags, JSONObject value, Throwable error) throws Exception {
        JSONObject event = SigningProbe.base(); event.put("run_id", config.getString("run_id"));
        event.put("case_id", "T-A13"); event.put("scenario", "binder"); event.put("query_path", path);
        event.put("package", target); event.put("flags", flags); event.put("event", error == null ? "response" : "failure");
        if (value.has("signers")) event.put("actual_signer_sha256", value.getJSONArray("signers"));
        event.put("response_marker", value.toString()); event.put("error_class", error == null ? JSONObject.NULL : error.getClass().getName());
        Log.i("REPACK_FIXTURE", event.toString());
    }
    private static boolean unknown(IBinder binder) throws Exception {
        Parcel request = Parcel.obtain(), response = Parcel.obtain();
        try { request.writeInterfaceToken(DESCRIPTOR); return binder.transact(0x00fffffe, request, response, 0); }
        finally { request.recycle(); response.recycle(); }
    }
    public static void fromAsset(Context context) {
        try (InputStream input = context.getAssets().open("repack-fixture-binder.json")) {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream(); byte[] buffer = new byte[1024];
            for (int count; (count = input.read(buffer)) != -1;) bytes.write(buffer, 0, count);
            config = new JSONObject(bytes.toString("UTF-8")); String self = context.getPackageName();
            Method getService = Class.forName("android.os.ServiceManager").getDeclaredMethod("getService", String.class);
            getService.setAccessible(true);
            IBinder before = (IBinder) getService.invoke(null, "package"); Object retained = asInterface(before);
            if (config.getBoolean("deferred")) {
                context.getPackageManager(); // Create a genuine existing manager before late publication.
                Class.forName("dev.repack.shim.Bootstrap").getMethod("fixturePublish", Context.class, boolean.class).invoke(null, context, false);
            }
            IBinder wrapper = (IBinder) getService.invoke(null, "package"); Object fresh = asInterface(wrapper);
            Field rawField = Class.forName("dev.repack.shim.PackageBinder").getDeclaredField("original"); rawField.setAccessible(true);
            IBinder raw = (IBinder) rawField.get(null); Object real = asInterface(raw);
            for (int flags : new int[] {PackageManager.GET_SIGNATURES, PackageManager.GET_SIGNING_CERTIFICATES}) {
                String suffix = flags == PackageManager.GET_SIGNATURES ? "legacy" : "current";
                for (String target : new String[] {self, "dev.repack.fixture.other"})
                    emit("fresh-" + (target.equals(self) ? "self-" : "other-") + suffix, target, flags, info(query(fresh, target, flags), flags), null);
                emit("original-proxy-" + suffix, self, flags, info(query(real, self, flags), flags), null);
                emit("wrapped-transact-" + suffix, self, flags, info(transact(wrapper, self, flags), flags), null);
                emit("raw-transact-" + suffix, self, flags, info(transact(raw, self, flags), flags), null);
                if (config.getBoolean("deferred")) emit("retained-before-" + suffix, self, flags, info(query(retained, self, flags), flags), null);
            }
            emit("fresh-missing", self, 0, info(query(fresh, "dev.repack.fixture.missing", PackageManager.GET_SIGNING_CERTIFICATES), PackageManager.GET_SIGNING_CERTIFICATES), null);
            emit("raw-missing", self, 0, info(query(real, "dev.repack.fixture.missing", PackageManager.GET_SIGNING_CERTIFICATES), PackageManager.GET_SIGNING_CERTIFICATES), null);
            final boolean[] died = new boolean[] {false};
            IBinder.DeathRecipient recipient = new IBinder.DeathRecipient() { public void binderDied() { died[0] = true; } };
            wrapper.linkToDeath(recipient, 0); boolean unlink = wrapper.unlinkToDeath(recipient, 0);
            IBinder.DeathRecipient rawRecipient = new IBinder.DeathRecipient() { public void binderDied() { died[0] = true; } };
            raw.linkToDeath(rawRecipient, 0); boolean rawUnlink = raw.unlinkToDeath(rawRecipient, 0);
            JSONObject operations = new JSONObject(); operations.put("descriptor", wrapper.getInterfaceDescriptor());
            operations.put("alive_matches", wrapper.isBinderAlive() == raw.isBinderAlive());
            operations.put("ping_matches", wrapper.pingBinder() == raw.pingBinder());
            operations.put("as_binder_wrapper", ((IInterface) fresh).asBinder() == wrapper);
            operations.put("matching_local_interface", wrapper.queryLocalInterface(DESCRIPTOR) == fresh);
            operations.put("unrelated_interface_matches", wrapper.queryLocalInterface("dev.repack.fixture.unrelated") == raw.queryLocalInterface("dev.repack.fixture.unrelated"));
            operations.put("same_cached_wrapper", getService.invoke(null, "package") == wrapper);
            operations.put("wrapper_reflexive", wrapper.equals(wrapper)); operations.put("interface_reflexive", fresh.equals(fresh));
            operations.put("stable_hash", wrapper.hashCode() == wrapper.hashCode());
            operations.put("unlink_matches", unlink == rawUnlink && unlink); operations.put("death_observed", died[0]);
            operations.put("unknown_transaction_matches", unknown(wrapper) == unknown(raw));
            operations.put("before_is_wrapper", before == wrapper);
            emit("binder-operations", self, 0, operations, null);
        } catch (FileNotFoundException absent) {
            // Normal fixtures contain no Binder experiment asset.
        } catch (Throwable error) {
            try { if (config != null) emit("failure", context.getPackageName(), 0, new JSONObject(), error); }
            catch (Exception serialization) { throw new IllegalStateException(serialization); }
        }
    }
}
