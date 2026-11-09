import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.security.*;
import javax.net.ssl.*;
public final class FixtureTLSServer {
    public static void main(String[] args) throws Exception {
        char[] password = new String(Files.readAllBytes(Paths.get(args[1])), "UTF-8").trim().toCharArray();
        KeyStore store = KeyStore.getInstance("PKCS12"); try (InputStream in = new FileInputStream(args[0])) { store.load(in, password); }
        KeyManagerFactory km = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()); km.init(store, password);
        SSLContext ctx = SSLContext.getInstance("TLS"); ctx.init(km.getKeyManagers(), null, null);
        SSLServerSocket server = (SSLServerSocket)ctx.getServerSocketFactory().createServerSocket(Integer.parseInt(args[3]), 8, InetAddress.getByName(args[2]));
        server.setEnabledProtocols(new String[]{"TLSv1.2"}); System.out.println("READY"); System.out.flush();
        while (true) {
            try (SSLSocket socket = (SSLSocket)server.accept()) { socket.setSoTimeout(6000); socket.startHandshake(); socket.getOutputStream().write(79); socket.getOutputStream().flush(); }
            catch (SSLException expected) { System.out.println("EXPECTED_CLIENT_REJECTION"); System.out.flush(); }
        }
    }
}
