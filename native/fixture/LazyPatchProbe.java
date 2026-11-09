package dev.repack.fixture.common;

/** Appended only to the native coexistence fixture, then loaded by name under active hooks. */
public final class LazyPatchProbe implements javax.net.ssl.HostnameVerifier {
    public boolean verify(String host, javax.net.ssl.SSLSession session) {
        if (session == null || !"pinned-native.invalid".equals(host)) return false;
        try {
            byte[] key = session.getPeerCertificates()[0].getPublicKey().getEncoded();
            byte[] fingerprint = java.security.MessageDigest.getInstance("SHA-256").digest(key);
            return java.util.Arrays.equals(fingerprint, new byte[32]);
        } catch (Exception invalid) { return false; }
    }
    public String unrelated() { return "preserved-method"; }
}
