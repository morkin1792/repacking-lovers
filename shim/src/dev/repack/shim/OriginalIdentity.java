package dev.repack.shim;

import android.content.pm.Signature;
import android.content.pm.SigningInfo;
import android.os.Build;
import android.os.Parcel;
import android.util.Base64;
import java.io.ByteArrayInputStream;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.json.JSONArray;
import org.json.JSONObject;

/** API30-only public Parcel adapter; its internal wire layout is tested separately. */
final class OriginalIdentity {
    private static SigningInfo template;
    static Signature[] signatures() {
        Signature[] result = new Signature[RepackConfig.ORIGINAL_CERTIFICATES.length];
        for (int i = 0; i < result.length; i++) result[i] = new Signature(Base64.decode(RepackConfig.ORIGINAL_CERTIFICATES[i], Base64.NO_WRAP));
        return result;
    }
    static Signature[] history() {
        Signature[] result = new Signature[RepackConfig.ORIGINAL_HISTORY.length];
        for (int i = 0; i < result.length; i++) result[i] = new Signature(Base64.decode(RepackConfig.ORIGINAL_HISTORY[i], Base64.NO_WRAP));
        return result;
    }
    static Signature[] legacySignatures() {
        Signature[] current = signatures(), past = history();
        return current.length == 1 && past.length > 0 ? new Signature[] {past[0]} : current;
    }
    static synchronized SigningInfo signingInfo() throws Exception {
        if (template == null) template = buildSigningInfo();
        Parcel parcel = Parcel.obtain();
        try {
            template.writeToParcel(parcel, 0); parcel.setDataPosition(0);
            SigningInfo copy = SigningInfo.CREATOR.createFromParcel(parcel);
            if (parcel.dataAvail() != 0) throw new IllegalStateException("SigningInfo copy left unread Parcel data");
            return copy;
        } finally { parcel.recycle(); }
    }
    private static SigningInfo buildSigningInfo() throws Exception {
        if (Build.VERSION.SDK_INT != 30) throw new UnsupportedOperationException("Public Parcel adapter is validated only for API30");
        Signature[] current = signatures();
        if (current.length == 0) throw new IllegalStateException("Missing original certificates");
        CertificateFactory parser = CertificateFactory.getInstance("X.509");
        List<PublicKey> keys = new ArrayList<>();
        for (Signature certificate : current) {
            PublicKey key = parser.generateCertificate(new ByteArrayInputStream(certificate.toByteArray())).getPublicKey();
            if (!keys.contains(key)) keys.add(key);
        }
        Parcel parcel = Parcel.obtain();
        try {
            parcel.writeInt(RepackConfig.FIXTURE_BAD_SIGNING_LAYOUT ? 1 : 0);
            parcel.writeTypedArray(current, 0);
            parcel.writeInt(RepackConfig.ORIGINAL_SCHEME);
            parcel.writeInt(keys.size()); // Public encoding of ArraySet's count/writeValue elements.
            for (PublicKey key : keys) parcel.writeValue(key);
            Signature[] past = history();
            parcel.writeTypedArray(past.length == 0 ? null : past, 0);
            parcel.setDataPosition(0);
            SigningInfo info = SigningInfo.CREATOR.createFromParcel(parcel);
            if (parcel.dataAvail() != 0) throw new IllegalStateException("SigningInfo adapter left unread Parcel data");
            return info;
        } finally { parcel.recycle(); }
    }
    static JSONArray digests(Signature[] values) throws Exception {
        List<String> result = new ArrayList<>();
        if (values != null) for (Signature value : values) result.add(PlatformAccess.digest(value));
        Collections.sort(result);
        return new JSONArray(result);
    }
    static JSONArray orderedDigests(Signature[] values) throws Exception {
        JSONArray result = new JSONArray();
        if (values != null) for (Signature value : values) result.put(PlatformAccess.digest(value));
        return result;
    }
    static void selfTest() {
        JSONObject details = new JSONObject();
        try {
            details.put("capability", "identity-metadata");
            details.put("probe_token", RepackConfig.PROBE_TOKEN);
            details.put("adapter", "public-parcel-api30");
            details.put("bypass_active", false);
            SigningInfo actual = signingInfo();
            Parcel roundtrip = Parcel.obtain();
            SigningInfo copied;
            try {
                actual.writeToParcel(roundtrip, 0); roundtrip.setDataPosition(0);
                copied = SigningInfo.CREATOR.createFromParcel(roundtrip);
                if (roundtrip.dataAvail() != 0) throw new IllegalStateException("Roundtrip did not consume the Parcel");
            } finally { roundtrip.recycle(); }
            JSONArray current = digests(actual.getApkContentsSigners());
            JSONArray history = orderedDigests(actual.getSigningCertificateHistory());
            JSONArray repeated = digests(copied.getApkContentsSigners());
            JSONArray repeatedHistory = orderedDigests(copied.getSigningCertificateHistory());
            if (!current.toString().equals(repeated.toString()) || actual.hasMultipleSigners() != copied.hasMultipleSigners()
                    || actual.hasPastSigningCertificates() != copied.hasPastSigningCertificates()
                    || !history.toString().equals(repeatedHistory.toString())) {
                throw new IllegalStateException("SigningInfo roundtrip changed public semantics");
            }
            details.put("actual_signer_sha256", current);
            details.put("actual_history_sha256", history);
            details.put("roundtrip_signer_sha256", repeated);
            details.put("roundtrip_history_sha256", repeatedHistory);
            details.put("history_null", actual.getSigningCertificateHistory() == null);
            details.put("has_multiple_signers", actual.hasMultipleSigners());
            details.put("has_past_signing_certificates", actual.hasPastSigningCertificates());
            details.put("outcome", "passed");
            Bootstrap.event("complete", "initEarly", details, null);
        } catch (Exception error) {
            try { details.put("outcome", "failed"); }
            catch (Exception serialization) { throw new IllegalStateException(serialization); }
            Bootstrap.event("failure", "initEarly", details, error);
        }
    }
}
