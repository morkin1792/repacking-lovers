package dev.repack.fixture.common;

import android.content.Context;
import java.io.InputStream;
import java.io.FileNotFoundException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateFactorySpi;
import java.security.cert.CertificateException;
import java.security.cert.CRLException;
import java.util.Collection;

/** An app-local provider change must not break otherwise valid PM signing-info lookups. */
public final class CryptoProbe {
    public static int calls;
    public static final class RejectingFactory extends CertificateFactorySpi {
        public java.security.cert.Certificate engineGenerateCertificate(InputStream input) throws CertificateException {
            calls++; throw new CertificateException("fixture-x509-provider");
        }
        public Collection<? extends java.security.cert.Certificate> engineGenerateCertificates(InputStream input) throws CertificateException {
            calls++; throw new CertificateException("fixture-x509-provider");
        }
        public java.security.cert.CRL engineGenerateCRL(InputStream input) throws CRLException { throw new CRLException("fixture"); }
        public Collection<? extends java.security.cert.CRL> engineGenerateCRLs(InputStream input) throws CRLException { throw new CRLException("fixture"); }
    }
    public static void fromAsset(Context context) {
        try (InputStream input = context.getAssets().open("repack-fixture-x509-provider.json")) {
            if (input.read() < 0) throw new IllegalStateException("Empty provider fixture asset");
            Provider provider = new Provider("RepackFixtureX509", 1.0, "Owned process-local test provider") {};
            provider.put("CertificateFactory.X.509", RejectingFactory.class.getName());
            if (Security.insertProviderAt(provider, 1) != 1) throw new IllegalStateException("Fixture provider was not first");
            SigningProbe.marker("fixture-x509-provider-installed");
        } catch (FileNotFoundException absent) {
            // Ordinary fixtures retain their normal provider list.
        } catch (Exception error) { throw new IllegalStateException(error); }
    }
    private CryptoProbe() {}
}
