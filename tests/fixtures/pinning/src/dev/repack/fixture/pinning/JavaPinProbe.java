package dev.repack.fixture.pinning;

import android.util.Log;
import java.net.URL;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.Socket;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.SSLParameters;
import okhttp3.CertificatePinner;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

public final class JavaPinProbe {
    private static X509TrustManager systemManager() throws Exception {
        TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        factory.init((KeyStore) null);
        for (TrustManager manager : factory.getTrustManagers()) if (manager instanceof X509TrustManager) return (X509TrustManager) manager;
        throw new IllegalStateException("No actual X509 trust manager");
    }
    static boolean pinned(Certificate certificate) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(certificate.getPublicKey().getEncoded());
        return Arrays.equals(digest, new byte[32]);
    }
    public static class PinTrustBase {
        private final X509TrustManager delegate;
        public PinTrustBase() throws Exception { delegate = systemManager(); }
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            delegate.checkClientTrusted(chain, authType);
        }
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            delegate.checkServerTrusted(chain, authType);
            try { if (pinned(chain[0])) return; }
            catch (Exception error) { throw new CertificateException(error); }
            throw new CertificateException("Fixture certificate pin mismatch");
        }
        public X509Certificate[] getAcceptedIssuers() { return delegate.getAcceptedIssuers(); }
        // Same-name, unsupported contract: the matcher must preserve this overload.
        public String checkServerTrusted(X509Certificate[] chain, String authType, boolean extra) {
            return "Unrelated certificate pin mismatch helper";
        }
    }
    public static final class InheritedPinTrust extends PinTrustBase implements X509TrustManager {
        public InheritedPinTrust() throws Exception { super(); }
    }
    public static final class DirectPinTrust implements X509TrustManager {
        private final X509TrustManager delegate;
        public DirectPinTrust() throws Exception { delegate = systemManager(); }
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            delegate.checkClientTrusted(chain, authType);
        }
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            delegate.checkServerTrusted(chain, authType);
            try { if (pinned(chain[0])) return; }
            catch (Exception error) { throw new CertificateException(error); }
            throw new CertificateException("Fixture certificate pin mismatch");
        }
        public X509Certificate[] getAcceptedIssuers() { return delegate.getAcceptedIssuers(); }
    }
    public static class PinHostnameBase {
        public boolean verify(String host, SSLSession session) {
            try { if (pinned(session.getPeerCertificates()[0])) return true; }
            catch (Exception failure) { /* Keep the verifier's boolean contract. */ }
            Log.i("REPACK_PIN_FIXTURE", "Fixture hostname pin mismatch");
            return false;
        }
    }
    public static final class InheritedPinHostname extends PinHostnameBase implements HostnameVerifier {}
    public static final class DirectPinHostname implements HostnameVerifier {
        public boolean verify(String host, SSLSession session) {
            try { if (pinned(session.getPeerCertificates()[0])) return true; }
            catch (Exception failure) { /* Same contract in a directly declared implementation. */ }
            Log.i("REPACK_PIN_FIXTURE", "Fixture hostname pin mismatch");
            return false;
        }
    }
    public abstract static class AbstractPinTrust implements X509TrustManager {
        public abstract void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException;
    }
    public abstract static class NativePinTrust implements X509TrustManager {
        public native void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException;
    }
    public static void unrelated(String host, List<Certificate> values) {
        Log.i("REPACK_PIN_FIXTURE", "Certificate pinning failure!");
    }
    private static void inlineGuard(Certificate certificate) throws Exception {
        if (!pinned(certificate)) throw new javax.net.ssl.SSLPeerUnverifiedException("Fixture inlined certificate pin mismatch");
    }
    public static String perform(URL url, String client) throws Exception {
        if (client.equals("inlined-pinner")) {
            Proxy proxy = ProxySelector.getDefault().select(url.toURI()).get(0);
            if (proxy.type() != Proxy.Type.HTTP) throw new IllegalStateException("Missing controlled HTTP proxy");
            try (Socket tcp = new Socket()) {
                tcp.connect(proxy.address(), 4000); tcp.setSoTimeout(4000);
                tcp.getOutputStream().write(("CONNECT " + url.getHost() + ":" + url.getPort()
                        + " HTTP/1.1\r\nHost: " + url.getHost() + ":" + url.getPort() + "\r\n\r\n")
                        .getBytes(StandardCharsets.US_ASCII));
                ByteArrayOutputStream headers = new ByteArrayOutputStream();
                while (!headers.toString("US-ASCII").endsWith("\r\n\r\n")) {
                    int value = tcp.getInputStream().read();
                    if (value < 0 || headers.size() > 16384) throw new IllegalStateException("Invalid CONNECT response");
                    headers.write(value);
                }
                if (!headers.toString("US-ASCII").startsWith("HTTP/1.1 200")) throw new IllegalStateException("CONNECT rejected");
                SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
                try (SSLSocket tls = (SSLSocket) factory.createSocket(tcp, url.getHost(), url.getPort(), true)) {
                    SSLParameters parameters = tls.getSSLParameters(); parameters.setEndpointIdentificationAlgorithm("HTTPS");
                    tls.setSSLParameters(parameters); tls.startHandshake();
                    inlineGuard(tls.getSession().getPeerCertificates()[0]);
                    tls.getOutputStream().write(("GET " + url.getFile() + " HTTP/1.0\r\nHost: " + url.getHost()
                            + "\r\nConnection: close\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
                    ByteArrayOutputStream response = new ByteArrayOutputStream(); byte[] buffer = new byte[1024];
                    for (int count; (count = tls.getInputStream().read(buffer)) != -1;) {
                        response.write(buffer, 0, count);
                        if (response.size() > 65536) throw new IllegalStateException("Oversized oracle response");
                    }
                    String text = response.toString("UTF-8"); return text.substring(text.indexOf("\r\n\r\n") + 4);
                }
            }
        }
        OkHttpClient.Builder builder = new OkHttpClient.Builder().callTimeout(4, TimeUnit.SECONDS)
                .connectTimeout(4, TimeUnit.SECONDS).readTimeout(4, TimeUnit.SECONDS);
        if (client.equals("okhttp")) {
            builder.certificatePinner(new CertificatePinner.Builder().add(url.getHost(),
                    "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").build());
        } else if (client.equals("trust-manager") || client.equals("inherited-trust-manager")) {
            X509TrustManager manager = client.equals("trust-manager") ? new DirectPinTrust() : new InheritedPinTrust();
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, new TrustManager[] { manager }, null);
            builder.sslSocketFactory(context.getSocketFactory(), manager);
        } else if (client.equals("hostname-verifier")) builder.hostnameVerifier(new DirectPinHostname());
        else if (client.equals("inherited-hostname-verifier")) builder.hostnameVerifier(new InheritedPinHostname());
        else if (!client.equals("okhttp-unpinned")) throw new IllegalArgumentException("Unknown client");
        try (Response response = builder.build().newCall(new Request.Builder().url(url).build()).execute()) {
            if (!response.isSuccessful() || response.body() == null) throw new IllegalStateException("Oracle HTTP response");
            return response.body().string();
        }
    }
}
