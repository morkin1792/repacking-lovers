package dev.repack.fixture.expansion;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;
import java.io.*;
import java.lang.reflect.*;
import java.nio.ByteBuffer;
import java.security.cert.*;
import java.util.*;
import java.util.concurrent.*;
import javax.net.ssl.*;
import org.chromium.net.*;
import org.json.JSONObject;

/** Owned ART/native fixture; real Cronet and hostname implementations. */
public final class ExpansionActivity extends Activity {
    volatile String lastCronetError;
    static native String nativeProbe(String library, int port, int variant);
    static void check(boolean ok, String text) { if (!ok) throw new AssertionError(text); }
    void cronet(String url, boolean accept) throws Exception {
        ExperimentalCronetEngine.Builder builder = new ExperimentalCronetEngine.Builder(this);
        builder.enableQuic(false).enableHttp2(false);
        builder.setExperimentalOptions("{\"HostResolverRules\":{\"host_resolver_rules\":\"MAP pinned.localhost 127.0.0.1\"}}");
        builder.addPublicKeyPins("pinned.localhost", Collections.singleton(new byte[32]), false, new Date(System.currentTimeMillis() + 86400000L));
        builder.enablePublicKeyPinningBypassForLocalTrustAnchors(false);
        Field delegateField = CronetEngine.Builder.class.getDeclaredField("mBuilderDelegate"); delegateField.setAccessible(true);
        Object delegate = delegateField.get(builder);
        Class<?> implementation = Class.forName("org.chromium.net.impl.CronetEngineBuilderImpl");
        for (int depth = 0; !implementation.isInstance(delegate) && depth < 8; depth++) {
            Method unwrap = delegate.getClass().getDeclaredMethod("getDelegate"); unwrap.setAccessible(true); delegate = unwrap.invoke(delegate);
        }
        check(implementation.isInstance(delegate), "expected embedded Cronet builder");
        Method pins = implementation.getDeclaredMethod("publicKeyPins"); pins.setAccessible(true);
        boolean patched = getIntent().getBooleanExtra("patched", false);
        check(((List<?>)pins.invoke(delegate)).size() == (patched ? 0 : 1), "Cronet public-key pin configuration");
        CronetEngine engine = builder.build();
        ExecutorService executor = Executors.newSingleThreadExecutor(); CountDownLatch done = new CountDownLatch(1);
        boolean[] success = {false}; Throwable[] error = {null}; StringBuilder body = new StringBuilder();
        UrlRequest.Callback callback = new UrlRequest.Callback() {
            public void onRedirectReceived(UrlRequest r, UrlResponseInfo i, String u) { error[0] = new AssertionError("unexpected redirect"); r.cancel(); done.countDown(); }
            public void onResponseStarted(UrlRequest r, UrlResponseInfo i) { if (i.getHttpStatusCode() != 200) error[0] = new AssertionError("HTTP " + i.getHttpStatusCode()); r.read(ByteBuffer.allocateDirect(8192)); }
            public void onReadCompleted(UrlRequest r, UrlResponseInfo i, ByteBuffer b) { b.flip(); byte[] bytes = new byte[b.remaining()]; b.get(bytes); body.append(new String(bytes, java.nio.charset.StandardCharsets.UTF_8)); b.clear(); r.read(b); }
            public void onSucceeded(UrlRequest r, UrlResponseInfo i) { success[0] = true; done.countDown(); }
            public void onFailed(UrlRequest r, UrlResponseInfo i, CronetException e) { error[0] = e; lastCronetError = e.toString(); done.countDown(); }
            public void onCanceled(UrlRequest r, UrlResponseInfo i) { done.countDown(); }
        };
        UrlRequest request = engine.newUrlRequestBuilder(url, callback, executor).build();
        try {
            request.start(); check(done.await(15, TimeUnit.SECONDS), "Cronet callback timeout");
            check(success[0] == accept, "Cronet result=" + success[0] + " error=" + error[0]);
            if (accept) check(body.toString().contains(getIntent().getStringExtra("token")), "marked HTTP response");
            else check(error[0] != null && error[0].toString().contains("CERT"), "expected certificate rejection " + error[0]);
        } finally { request.cancel(); engine.shutdown(); executor.shutdownNow(); }
    }
    void hostname(boolean relax) throws Exception {
        X509Certificate cert;
        try (InputStream in = getAssets().open("origin.der")) { cert = (X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(in); }
        SSLSession session = (SSLSession)Proxy.newProxyInstance(getClassLoader(), new Class<?>[]{SSLSession.class}, (p,m,a) -> {
            if (m.getName().equals("getPeerCertificates")) return new java.security.cert.Certificate[]{cert};
            throw new AssertionError(m.getName());
        });
        HostnameVerifier verifier = (HostnameVerifier)Class.forName("okhttp3.internal.tls.OkHostnameVerifier").getField("INSTANCE").get(null);
        check(verifier.verify("wrong.test", session) == relax, "OkHttp wrong-host decision");
        check(verifier.verify("127.0.0.1", session), "OkHttp matching host");
        org.apache.http.conn.ssl.BrowserCompatHostnameVerifier apache = new org.apache.http.conn.ssl.BrowserCompatHostnameVerifier();
        boolean accepted = true;
        try { apache.verify("wrong.test", cert); }
        catch (SSLException e) { accepted = false; }
        check(accepted == relax, "Apache wrong-host decision");
    }
    @Override public void onCreate(Bundle state) {
        super.onCreate(state); TextView view = new TextView(this); view.setText("Owned TLS expansion fixture"); setContentView(view);
        new Thread(() -> {
            JSONObject result = new JSONObject();
            try {
                String mode = getIntent().getStringExtra("case"); boolean patched = getIntent().getBooleanExtra("patched", false);
                result.put("token", getIntent().getStringExtra("token")); result.put("case", mode); result.put("patched", patched);
                result.put("uid", android.os.Process.myUid()); result.put("pid", android.os.Process.myPid()); result.put("target_sdk", getApplicationInfo().targetSdkVersion);
                check(android.os.Process.myUid() >= 10000 && getApplicationInfo().targetSdkVersion == 35, "ordinary app required");
                if (mode.equals("hostname")) hostname(patched);
                else if (mode.startsWith("cronet")) {
                    cronet(getIntent().getStringExtra("url"), patched && !mode.equals("cronet-wrong-host"));
                    result.put("cronet_error", lastCronetError);
                }
                else {
                    System.loadLibrary("repack_tls_probe");
                    String nativeText = nativeProbe(getIntent().getStringExtra("library"), getIntent().getIntExtra("port", 18443), getIntent().getIntExtra("variant", 0));
                    JSONObject nativeResult = new JSONObject(nativeText); result.put("native", nativeResult);
                    check(nativeResult.optString("error").isEmpty(), nativeText);
                    check(nativeResult.getBoolean("connected") == patched, "native TLS decision " + nativeText);
                    if (patched) check(nativeResult.getLong("verify_result") == 0 && nativeResult.getBoolean("peer") && nativeResult.getBoolean("payload"), "native session side effects " + nativeText);
                }
                result.put("ok", true); runOnUiThread(() -> view.setText("PASS " + mode));
            } catch (Throwable error) {
                try { result.put("ok", false); result.put("error", error.toString()); } catch (Exception ignored) {}
                Log.e("REPACK_EXPANSION", "failure", error);
            } finally { Log.i("REPACK_EXPANSION", result.toString()); }
        }, "owned-expansion").start();
    }
}
