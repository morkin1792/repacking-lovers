package com.appmattus.certificatetransparency.internal.verifier;
import java.io.IOException;
import java.util.List;
import javax.net.ssl.SSLPeerUnverifiedException;
import okhttp3.Interceptor;
import okhttp3.Response;
/** Deliberately lacks the base selector: exercises the constrained fallback. */
public final class CertificateTransparencyInterceptor implements Interceptor {
    private boolean verifyCertificateTransparency(String host, List<?> chain) { return false; }
    public Response intercept(Chain chain) throws IOException {
        if (!verifyCertificateTransparency(chain.request().url().host(), java.util.Collections.emptyList()))
            throw new SSLPeerUnverifiedException("Fixture Certificate Transparency rejection");
        return chain.proceed(chain.request());
    }
}
