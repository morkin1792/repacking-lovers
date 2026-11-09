import java.io.*;
import java.lang.reflect.*;
import java.net.*;
import java.security.*;
import java.security.cert.*;
import java.util.*;
import java.util.concurrent.*;
import javax.net.ssl.*;
import io.flutter.plugin.common.MethodCall;
import io.flutter.plugin.common.MethodChannel;
import okhttp3.*;

/** Executes real libraries after D8 -> shadow rewrite -> dex2jar translation.
 * Android/Flutter scheduling adapters are local stubs, not ART or a Dart engine.
 */
public final class HostHarness {
    static void check(boolean value, String message) { if (!value) throw new AssertionError(message); }
    static boolean patched;
    static X509Certificate certificate;
    static Object allocate(Class<?> cls) throws Exception {
        Class<?> u = Class.forName("sun.misc.Unsafe"); Field f = u.getDeclaredField("theUnsafe"); f.setAccessible(true);
        return u.getMethod("allocateInstance", Class.class).invoke(f.get(null), cls);
    }
    static void okhttp() throws Exception {
        CertificatePinner pinner = new CertificatePinner.Builder().add("fixture.test", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").build();
        int refused = 0;
        try { pinner.check("fixture.test", Collections.<java.security.cert.Certificate>singletonList(certificate)); }
        catch (SSLPeerUnverifiedException expected) { refused++; }
        try { pinner.check("fixture.test", certificate); }
        catch (SSLPeerUnverifiedException expected) { refused++; }
        check(refused == (patched ? 0 : 2), "real OkHttp List/array result");
    }
    static void ct() throws Exception {
        Class<?> base = Class.forName("com.appmattus.certificatetransparency.internal.verifier.CertificateTransparencyBase");
        Object obj = allocate(base);
        for (String name : new String[]{"includeHosts", "excludeHosts"}) {
            Field field = base.getDeclaredField(name); field.setAccessible(true); field.set(obj, Collections.emptySet());
        }
        Method selector = base.getDeclaredMethod("enabledForCertificateTransparency", String.class); selector.setAccessible(true);
        check(((Boolean)selector.invoke(obj, "fixture.test")) == !patched, "real CT selector polarity");
        Method verify = base.getDeclaredMethod("verifyCertificateTransparency", String.class, List.class); verify.setAccessible(true);
        Object result = verify.invoke(obj, "fixture.test", Collections.emptyList());
        check(result.getClass().getName().contains(patched ? "DisabledForHost" : "NoCertificates"), "real CT decision contract");
        Class<?> wrapperType = Class.forName("com.appmattus.certificatetransparency.internal.verifier.CertificateTransparencyHostnameVerifier");
        Object wrapper = allocate(wrapperType);
        for (String name : new String[]{"includeHosts", "excludeHosts"}) {
            Field field = base.getDeclaredField(name); field.setAccessible(true); field.set(wrapper, Collections.emptySet());
        }
        Field delegate = wrapperType.getDeclaredField("delegate"); delegate.setAccessible(true);
        delegate.set(wrapper, (HostnameVerifier)(host, session) -> host.equals("fixture.test"));
        Field policy = wrapperType.getDeclaredField("failOnError"); policy.setAccessible(true);
        policy.set(wrapper, (kotlin.jvm.functions.Function1<Object, Boolean>)(failure -> true));
        SSLSession session = (SSLSession)java.lang.reflect.Proxy.newProxyInstance(HostHarness.class.getClassLoader(),
            new Class<?>[]{SSLSession.class}, (proxy, member, args) -> {
                if (member.getName().equals("getPeerCertificates")) return new java.security.cert.Certificate[0];
                throw new AssertionError(member.getName());
            });
        check(((HostnameVerifier)wrapper).verify("fixture.test", session) == patched, "CT wrapper result");
        check(!((HostnameVerifier)wrapper).verify("wrong.test", session), "normal hostname delegate was bypassed");
    }
    static void interceptor() throws Exception {
        final Request request = new Request.Builder().url("https://fixture.test/").header("X-Original", "keep").build();
        final Response response = new Response.Builder().request(request).protocol(Protocol.HTTP_1_1).code(200).message("fixture").build();
        final int[] calls = {0}; final IOException sentinel = new IOException("fixture-proceed"); final boolean[] fail = {false};
        Interceptor.Chain chain = (Interceptor.Chain)java.lang.reflect.Proxy.newProxyInstance(HostHarness.class.getClassLoader(),
            new Class<?>[]{Interceptor.Chain.class}, (proxy, method, args) -> {
                if (method.getName().equals("request")) return request;
                if (method.getName().equals("proceed")) {
                    calls[0]++; check(args[0] == request && "keep".equals(((Request)args[0]).header("X-Original")), "request identity/headers");
                    if (fail[0]) throw sentinel;
                    return response;
                }
                throw new AssertionError(method.getName());
            });
        Interceptor verifier = (Interceptor)Class.forName("com.appmattus.certificatetransparency.internal.verifier.CertificateTransparencyInterceptor").getConstructor().newInstance();
        try { check(verifier.intercept(chain) == response && patched, "response identity"); }
        catch (SSLPeerUnverifiedException expected) { check(!patched, "patched interceptor rejected"); }
        check(calls[0] == (patched ? 1 : 0), "exactly one proceed");
        if (patched) {
            fail[0] = true;
            try { verifier.intercept(chain); throw new AssertionError("exception swallowed"); }
            catch (IOException expected) { check(expected == sentinel, "exception identity"); }
            check(calls[0] == 2, "retry/duplicate proceed");
        }
    }
    static void plugins() throws Exception {
        final int[] fetched = {0};
        URL.setURLStreamHandlerFactory(protocol -> protocol.equals("https") ? new URLStreamHandler() {
            protected URLConnection openConnection(URL url) {
                return new HttpsURLConnection(url) {
                    public void connect() { fetched[0]++; check("keep".equals(getRequestProperty("X-Original")), "plugin headers changed"); }
                    public void disconnect() {}
                    public boolean usingProxy() { return false; }
                    public String getCipherSuite() { return "fixture"; }
                    public java.security.cert.Certificate[] getLocalCertificates() { return null; }
                    public java.security.cert.Certificate[] getServerCertificates() { return new java.security.cert.Certificate[]{certificate}; }
                };
            }
        } : null);
        for (String name : new String[]{"diefferson.http_certificate_pinning.HttpCertificatePinningPlugin", "com.macif.plugin.sslpinningplugin.SslPinningPlugin"}) {
            Object plugin = Class.forName(name).getConstructor().newInstance();
            HashMap<String, Object> config = new HashMap<>(); config.put("url", "https://fixture.test/");
            config.put("fingerprints", Arrays.asList("00000000")); config.put("headers", Collections.singletonMap("X-Original", "keep"));
            config.put("timeout", 2); config.put("type", "SHA-256"); config.put("httpMethod", "Get");
            CountDownLatch done = new CountDownLatch(1); final int[] count = {0}; final String[] outcome = {null};
            ((MethodChannel.MethodCallHandler)plugin).onMethodCall(new MethodCall("check", config), new MethodChannel.Result() {
                public void success(Object result) { count[0]++; outcome[0] = String.valueOf(result); done.countDown(); }
                public void error(String code, String message, Object details) { count[0]++; outcome[0] = code; done.countDown(); }
                public void notImplemented() { count[0]++; outcome[0] = "not-implemented"; done.countDown(); }
            });
            check(done.await(5, TimeUnit.SECONDS), "MethodChannel callback hung");
            check(count[0] == 1 && (patched ? "CONNECTION_SECURE" : "CONNECTION_NOT_SECURE").equals(outcome[0]), "actual plugin callback result " + outcome[0]);
            for (Field field : plugin.getClass().getDeclaredFields()) {
                if (ExecutorService.class.isAssignableFrom(field.getType())) { field.setAccessible(true); ((ExecutorService)field.get(plugin)).shutdownNow(); }
            }
        }
        check(fetched[0] == (patched ? 0 : 2), "fingerprint probe count");
    }
    static void conscrypt(String keystore, String password) throws Exception {
        KeyStore store = KeyStore.getInstance("PKCS12"); try (InputStream in = new FileInputStream(keystore)) { store.load(in, password.toCharArray()); }
        KeyManagerFactory km = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()); km.init(store, password.toCharArray());
        SSLContext serverContext = SSLContext.getInstance("TLS"); serverContext.init(km.getKeyManagers(), null, null);
        SSLServerSocket server = (SSLServerSocket)serverContext.getServerSocketFactory().createServerSocket(0, 1, InetAddress.getLoopbackAddress());
        server.setSoTimeout(5000); server.setEnabledProtocols(new String[]{"TLSv1.2"});
        Thread listener = new Thread(() -> {
            try (SSLSocket socket = (SSLSocket)server.accept()) { socket.setSoTimeout(5000); socket.startHandshake(); socket.getOutputStream().write(79); }
            catch (IOException expected) {} finally { try { server.close(); } catch (IOException ignored) {} }
        }); listener.setDaemon(true); listener.start();
        Provider provider = (Provider)Class.forName("org.conscrypt.Conscrypt").getMethod("newProvider").invoke(null);
        final int[] calls = {0};
        X509TrustManager rejecting = new X509TrustManager() {
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
            public void checkClientTrusted(X509Certificate[] c, String a) throws CertificateException { throw new CertificateException("client check preserved"); }
            public void checkServerTrusted(X509Certificate[] c, String a) throws CertificateException { calls[0]++; throw new CertificateException("fixture server rejection"); }
        };
        SSLContext clientContext = SSLContext.getInstance("TLS", provider); clientContext.init(null, new TrustManager[]{rejecting}, null);
        boolean connected = false;
        try (SSLSocket socket = (SSLSocket)clientContext.getSocketFactory().createSocket(InetAddress.getLoopbackAddress(), server.getLocalPort())) {
            socket.setSoTimeout(5000); socket.setEnabledProtocols(new String[]{"TLSv1.2"}); socket.startHandshake();
            check(socket.getSession().getPeerCertificates().length > 0, "peer-chain side effect lost");
            check(socket.getInputStream().read() == 79, "local TLS payload"); connected = true;
        } catch (SSLException expected) { check(!patched, "patched real Conscrypt failed: " + expected); }
        listener.join(6000);
        check(connected == patched && calls[0] == (patched ? 0 : 1), "Conscrypt decision/callback count");
    }
    public static void main(String[] args) throws Exception {
        patched = args[1].equals("patched");
        try (InputStream in = new FileInputStream(args[2])) { certificate = (X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(in); }
        switch (args[0]) {
            case "okhttp": okhttp(); break;
            case "ct": ct(); break;
            case "interceptor": interceptor(); break;
            case "plugins": plugins(); break;
            case "conscrypt": conscrypt(args[3], new String(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(args[4])), java.nio.charset.StandardCharsets.UTF_8).trim()); break;
            default: throw new IllegalArgumentException(args[0]);
        }
        System.out.println("PINNING_EXTENSION_PASS " + args[0] + " " + args[1]);
    }
}
