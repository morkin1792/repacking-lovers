package dev.repack.fixture.extensions;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;
import java.io.InputStream;
import java.lang.reflect.*;
import java.net.InetAddress;
import java.security.Provider;
import java.security.cert.*;
import java.util.*;
import javax.net.ssl.*;
import org.json.JSONObject;

/** Owned ordinary-app ART fixture. No framework/private-OS reflection. */
public final class AndroidProbeActivity extends Activity {
    static void check(boolean ok, String label) { if (!ok) throw new AssertionError(label); }
    static void field(Class<?> cls, Object obj, String name, Object value) throws Exception {
        Field f = cls.getDeclaredField(name); f.setAccessible(true); f.set(obj, value);
    }
    static void ct() throws Exception {
        ClassLoader loader = AndroidProbeActivity.class.getClassLoader();
        Class<?> sourceType = Class.forName("com.appmattus.certificatetransparency.datasource.DataSource");
        Object source = Proxy.newProxyInstance(loader, new Class<?>[]{sourceType}, (p, m, args) -> { throw new AssertionError("CT network data source must not run"); });
        Class<?> base = Class.forName("com.appmattus.certificatetransparency.internal.verifier.CertificateTransparencyBase");
        Object[] args = {Collections.emptySet(), Collections.emptySet(), null, null, null, source, null, null};
        Constructor<?> ctor = null;
        for (Constructor<?> c : base.getDeclaredConstructors()) if (c.getParameterTypes().length == 8) ctor = c;
        check(ctor != null, "CT constructor"); ctor.setAccessible(true); Object policy = ctor.newInstance(args);
        Method selector = base.getDeclaredMethod("enabledForCertificateTransparency", String.class); selector.setAccessible(true);
        check(((Boolean)selector.invoke(policy, "fixture.test")) == !HostHarness.patched, "CT polarity");
        Method verify = base.getDeclaredMethod("verifyCertificateTransparency", String.class, List.class); verify.setAccessible(true);
        check(verify.invoke(policy, "fixture.test", Collections.emptyList()).getClass().getName().contains(HostHarness.patched ? "DisabledForHost" : "NoCertificates"), "CT result");
        Class<?> wrapper = Class.forName("com.appmattus.certificatetransparency.internal.verifier.CertificateTransparencyHostnameVerifier");
        Constructor<?> wrapperCtor = null;
        for (Constructor<?> c : wrapper.getConstructors()) if (c.getParameterTypes().length == 11) wrapperCtor = c;
        check(wrapperCtor != null, "CT wrapper constructor");
        Object[] wrapperArgs = new Object[11]; wrapperArgs[0] = (HostnameVerifier)(host, session) -> host.equals("fixture.test");
        System.arraycopy(args, 0, wrapperArgs, 1, 8);
        wrapperArgs[9] = (kotlin.jvm.functions.Function1<Object, Boolean>)(failure -> true);
        HostnameVerifier verifier = (HostnameVerifier)wrapperCtor.newInstance(wrapperArgs);
        SSLSession session = (SSLSession)Proxy.newProxyInstance(loader, new Class<?>[]{SSLSession.class}, (p, m, a) -> {
            if (m.getName().equals("getPeerCertificates")) return new java.security.cert.Certificate[0];
            throw new AssertionError(m.getName());
        });
        check(verifier.verify("fixture.test", session) == HostHarness.patched, "CT wrapper");
        check(!verifier.verify("wrong.test", session), "hostname delegate lost");
    }
    static String conscrypt(int port, boolean engine) throws Exception {
        Class<?> api = Class.forName("org.conscrypt.Conscrypt");
        Provider provider = (Provider)api.getMethod("newProvider").invoke(null);
        final int[] calls = {0};
        X509TrustManager rejecting = new X509TrustManager() {
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
            public void checkClientTrusted(X509Certificate[] chain, String auth) throws CertificateException { throw new CertificateException("client auth preserved"); }
            public void checkServerTrusted(X509Certificate[] chain, String auth) throws CertificateException { calls[0]++; throw new CertificateException("fixture rejects server"); }
        };
        SSLContext context = SSLContext.getInstance("TLS", provider); context.init(null, new TrustManager[]{rejecting}, null);
        SSLSocketFactory factory = context.getSocketFactory();
        api.getMethod("setUseEngineSocket", SSLSocketFactory.class, boolean.class).invoke(null, factory, engine);
        String socketClass; boolean connected = false;
        try (SSLSocket socket = (SSLSocket)factory.createSocket(InetAddress.getByName("127.0.0.1"), port)) {
            socketClass = socket.getClass().getName();
            check(Class.forName("org.conscrypt." + (engine ? "ConscryptEngineSocket" : "ConscryptFileDescriptorSocket")).isInstance(socket), "wrong socket backend " + socketClass);
            socket.setSoTimeout(5000); socket.setEnabledProtocols(new String[]{"TLSv1.2"});
            try {
                socket.startHandshake();
                check(socket.getSession().getPeerCertificates().length > 0, "peer-chain updates lost");
                check(socket.getInputStream().read() == 79, "local TLS payload"); connected = true;
            } catch (SSLException expected) { check(!HostHarness.patched, "patched handshake failed " + expected); }
        }
        check(connected == HostHarness.patched, "TLS result");
        check(calls[0] == (HostHarness.patched ? 0 : 1), "server trust-call count " + calls[0]);
        return socketClass;
    }
    @Override public void onCreate(Bundle state) {
        super.onCreate(state); TextView view = new TextView(this); view.setText("Running owned pinning fixture"); setContentView(view);
        String mode = getIntent().getStringExtra("case"); String token = getIntent().getStringExtra("token");
        HostHarness.patched = getIntent().getBooleanExtra("patched", false);
        new Thread(() -> {
            JSONObject event = new JSONObject();
            try {
                event.put("token", token); event.put("case", mode); event.put("patched", HostHarness.patched);
                event.put("uid", android.os.Process.myUid()); event.put("pid", android.os.Process.myPid());
                event.put("target_sdk", getApplicationInfo().targetSdkVersion);
                check(android.os.Process.myUid() >= 10000 && getApplicationInfo().targetSdkVersion == 35, "ordinary target35 app required");
                try (InputStream in = getAssets().open("fixture.der")) { HostHarness.certificate = (X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(in); }
                switch (mode) {
                    case "okhttp": HostHarness.okhttp(); break;
                    case "ct": ct(); break;
                    case "interceptor": HostHarness.interceptor(); break;
                    case "plugins": HostHarness.plugins(); break;
                    case "conscrypt-engine": event.put("socket_class", conscrypt(getIntent().getIntExtra("tls_port", 18443), true)); break;
                    case "conscrypt-fd": event.put("socket_class", conscrypt(getIntent().getIntExtra("tls_port", 18443), false)); break;
                    default: throw new IllegalArgumentException(mode);
                }
                event.put("ok", true); runOnUiThread(() -> view.setText("PASS " + mode + " patched=" + HostHarness.patched));
            } catch (Throwable error) {
                try { event.put("ok", false); event.put("error_class", error.getClass().getName()); event.put("error", String.valueOf(error)); } catch (Exception ignored) {}
                Log.e("REPACK_ANDROID", "fixture failure", error); runOnUiThread(() -> view.setText("FAIL " + mode + " " + error));
            } finally { Log.i("REPACK_ANDROID", event.toString()); }
        }, "owned-pinning-fixture").start();
    }
}
