package dev.repack.fixture.common;

import android.app.Activity;
import android.content.Intent;
import android.content.pm.*;
import android.util.Base64;
import android.util.Log;
import android.widget.TextView;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.util.*;
import org.json.*;

/** Public API observations for M1b-1; expected values never supply the actual result. */
public final class ContractProbe {
    private static JSONArray digests(Signature[] signatures, boolean sort) throws Exception {
        List<String> values = new ArrayList<>();
        if (signatures != null) for (Signature signature : signatures) values.add(SigningProbe.digest(signature));
        if (sort) Collections.sort(values);
        return new JSONArray(values);
    }
    private static JSONObject metadata(PackageInfo info) throws Exception {
        JSONObject value = new JSONObject(); value.put("package", info.packageName);
        value.put("uid", info.applicationInfo.uid); value.put("source_dir", info.applicationInfo.sourceDir);
        value.put("version_code", info.getLongVersionCode());
        value.put("legacy", digests(info.signatures, true)); value.put("legacy_present", info.signatures != null);
        SigningInfo signing = info.signingInfo;
        value.put("current", digests(signing == null ? null : signing.getApkContentsSigners(), true));
        value.put("current_present", signing != null);
        value.put("history", digests(signing == null ? null : signing.getSigningCertificateHistory(), false));
        value.put("history_null", signing == null || signing.getSigningCertificateHistory() == null);
        value.put("multiple", signing != null && signing.hasMultipleSigners());
        value.put("past", signing != null && signing.hasPastSigningCertificates());
        return value;
    }
    public static void run(Activity activity, Intent intent) {
        try {
            JSONArray cases = new JSONArray(intent.getStringExtra("contract_json"));
            PackageManager manager = activity.getPackageManager();
            for (int i = 0; i < cases.length(); i++) {
                JSONObject config = cases.getJSONObject(i), event = SigningProbe.base();
                event.put("run_id", intent.getStringExtra("run_id")); event.put("case_id", intent.getStringExtra("case_id"));
                event.put("scenario", "signing-contracts"); event.put("query_path", config.getString("id"));
                event.put("package", config.optString("package", activity.getPackageName()));
                JSONObject observed = new JSONObject(); String operation = config.getString("operation");
                observed.put("operation", operation);
                try {
                    String target = config.optString("package", activity.getPackageName());
                    Object value;
                    if (operation.equals("predicate-package") || operation.equals("predicate-uid")) {
                        byte[] certificate = config.isNull("certificate") ? null : Base64.decode(config.getString("certificate"), Base64.NO_WRAP);
                        int type = config.getInt("certificate_type");
                        value = operation.equals("predicate-package") ? manager.hasSigningCertificate(target, certificate, type)
                                : manager.hasSigningCertificate(config.has("uid") ? config.getInt("uid") : manager.getApplicationInfo(target, 0).uid, certificate, type);
                    } else if (operation.equals("compare-package")) {
                        value = manager.checkSignatures(target, config.getString("other_package"));
                    } else if (operation.equals("compare-uid")) {
                        int first = config.has("first_uid") ? config.getInt("first_uid") : manager.getApplicationInfo(target, 0).uid;
                        int second = config.has("second_uid") ? config.getInt("second_uid") : manager.getApplicationInfo(config.getString("other_package"), 0).uid;
                        value = manager.checkSignatures(first, second);
                    } else if (operation.equals("metadata")) {
                        int flags = config.getInt("flags"); event.put("flags", flags);
                        value = metadata(manager.getPackageInfo(target, flags));
                    } else if (operation.equals("list-installed") || operation.equals("list-permissions")) {
                        int flags = config.getInt("flags"); event.put("flags", flags);
                        List<PackageInfo> packages = operation.equals("list-installed") ? manager.getInstalledPackages(flags)
                                : manager.getPackagesHoldingPermissions(new String[] {"dev.repack.fixture.permission.CONTRACT"}, flags);
                        JSONObject selected = new JSONObject(); MessageDigest digest = MessageDigest.getInstance("SHA-256");
                        for (PackageInfo info : packages) {
                            digest.update(info.packageName.getBytes(StandardCharsets.UTF_8)); digest.update((byte) '\n');
                            if (info.packageName.equals("dev.repack.fixture.identity") || info.packageName.equals("dev.repack.fixture.other"))
                                selected.put(info.packageName, metadata(info));
                        }
                        StringBuilder hash = new StringBuilder(); for (byte item : digest.digest()) hash.append(String.format(Locale.ROOT, "%02x", item & 255));
                        observed.put("list_order_sha256", hash.toString()); observed.put("list_count", packages.size());
                        value = selected;
                    } else if (operation.equals("installer")) {
                        InstallSourceInfo source = manager.getInstallSourceInfo(target);
                        JSONObject details = new JSONObject(); String legacy = manager.getInstallerPackageName(target);
                        details.put("legacy", legacy == null ? JSONObject.NULL : legacy);
                        details.put("installing", source.getInstallingPackageName() == null ? JSONObject.NULL : source.getInstallingPackageName());
                        details.put("initiating", source.getInitiatingPackageName() == null ? JSONObject.NULL : source.getInitiatingPackageName());
                        details.put("originating", source.getOriginatingPackageName() == null ? JSONObject.NULL : source.getOriginatingPackageName());
                        value = details;
                    } else throw new IllegalArgumentException("Unknown contract operation");
                    observed.put("value", value == null ? JSONObject.NULL : value);
                    event.put("event", "response"); event.put("comparison", "not-run");
                } catch (Exception error) {
                    event.put("event", "failure"); event.put("error_class", error.getClass().getName());
                    event.put("comparison", "failed");
                }
                observed.put("id", config.getString("id")); event.put("response_marker", observed.toString());
                Log.i("REPACK_FIXTURE", event.toString());
            }
            TextView view = new TextView(activity); view.setText("Repack signing contracts completed"); activity.setContentView(view);
        } catch (Exception error) { throw new IllegalStateException("Contract fixture failed", error); }
    }
}
