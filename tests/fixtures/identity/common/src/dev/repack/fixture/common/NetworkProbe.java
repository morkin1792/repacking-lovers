package dev.repack.fixture.common;

import android.app.Application;
import android.content.Context;
import android.os.Process;
import android.util.Log;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.FileNotFoundException;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.lang.reflect.InvocationTargetException;
import org.json.JSONArray;
import org.json.JSONObject;

public final class NetworkProbe {
    private NetworkProbe() {}

    private static String read(InputStream input) throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        for (int count; (count = input.read(buffer)) != -1;) {
            output.write(buffer, 0, count);
            if (output.size() > 65536) throw new IllegalStateException("Oversized oracle response");
        }
        return new String(output.toByteArray(), StandardCharsets.UTF_8);
    }

    public static void fromAsset(final Context context) {
        try (InputStream input = context.getAssets().open("repack-fixture-request.json")) {
            final JSONObject config = new JSONObject(read(input));
            SigningProbe.marker("application-network-start");
            new Thread(new Runnable() { public void run() { runRequest(context, config); } },
                    "repack-fixture-request").start();
        } catch (FileNotFoundException absent) {
            // Baseline fixtures have no network request asset.
        } catch (Exception error) { throw new IllegalStateException(error); }
    }

    public static void runRequest(Context context, JSONObject config) {
        JSONObject event = new JSONObject();
        HttpURLConnection connection = null;
        try {
            event.put("schema_version", 1);
            event.put("run_id", config.getString("run_id"));
            event.put("case_id", config.getString("case_id"));
            event.put("pid", Process.myPid());
            event.put("process", Application.getProcessName());
            event.put("event", "response");
            event.put("scenario", "routing");
            event.put("query_path", JSONObject.NULL);
            event.put("package", context.getPackageName());
            event.put("flags", JSONObject.NULL);
            event.put("actual_signer_sha256", new JSONArray());
            event.put("expected_signer_sha256", new JSONArray());
            event.put("comparison", "failed");
            event.put("response_marker", JSONObject.NULL);
            event.put("error_class", JSONObject.NULL);
            URL url = new URL(config.getString("url"));
            String token = config.getString("run_id");
            if (!(url.getHost().equals("127.0.0.1") || url.getHost().endsWith(".repack.test"))
                    || !url.getPath().equals("/repack/" + token) || !token.matches("[A-Za-z0-9_-]{8,120}")) {
                throw new IllegalArgumentException("Uncontrolled fixture URL");
            }
            String body;
            if (config.optBoolean("selector_probe")) {
                JSONObject observation = new JSONObject();
                ProxySelector selector = ProxySelector.getDefault();
                observation.put("selector_class", selector == null ? JSONObject.NULL : selector.getClass().getName());
                JSONArray selected = new JSONArray();
                if (selector != null) for (Proxy proxy : selector.select(url.toURI())) selected.put(proxy.toString());
                observation.put("selected", selected);
                for (String property : new String[] {"http.proxyHost", "http.proxyPort", "https.proxyHost", "https.proxyPort"}) {
                    observation.put(property, System.getProperty(property, ""));
                }
                event.put("event", "marker");
                event.put("response_marker", observation.toString());
                event.put("comparison", "passed");
                Log.i("REPACK_FIXTURE", event.toString());
                return;
            } else if (config.optBoolean("direct_socket")) {
                if (!url.getProtocol().equals("http") || !url.getHost().equals("127.0.0.1")) {
                    throw new IllegalArgumentException("Direct socket control is loopback HTTP only");
                }
                try (Socket socket = new Socket()) {
                    socket.connect(new InetSocketAddress(url.getHost(), url.getPort()), 4000);
                    socket.setSoTimeout(4000);
                    socket.getOutputStream().write(("GET " + url.getFile() + " HTTP/1.0\r\nHost: "
                            + url.getHost() + "\r\nConnection: close\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
                    String response = read(socket.getInputStream());
                    if (!response.startsWith("HTTP/1.0 200") && !response.startsWith("HTTP/1.1 200")) {
                        throw new IllegalStateException("Origin status");
                    }
                    body = response.substring(response.indexOf("\r\n\r\n") + 4);
                }
            } else if (config.has("client")) {
                try {
                    body = (String) Class.forName("dev.repack.fixture.pinning.JavaPinProbe")
                            .getMethod("perform", URL.class, String.class).invoke(null, url, config.getString("client"));
                } catch (InvocationTargetException error) {
                    Throwable cause = error.getCause();
                    if (cause instanceof Exception) throw (Exception) cause;
                    throw new IllegalStateException(cause);
                }
            } else {
                connection = (HttpURLConnection) (config.optBoolean("explicit_direct")
                        ? url.openConnection(Proxy.NO_PROXY) : url.openConnection());
                connection.setConnectTimeout(4000);
                connection.setReadTimeout(4000);
                connection.setUseCaches(false);
                connection.setInstanceFollowRedirects(false);
                if (connection.getResponseCode() != 200) throw new IllegalStateException("Proxy status");
                try (InputStream input = connection.getInputStream()) { body = read(input); }
            }
            event.put("response_marker", body);
            JSONObject response = new JSONObject(body);
            event.put("comparison", token.equals(response.optString("token"))
                    && config.getString("expected_via").equals(response.optString("via")) ? "passed" : "failed");
        } catch (Exception failure) {
            try {
                event.put("event", "failure");
                event.put("error_class", failure.getClass().getName());
            } catch (Exception error) { throw new IllegalStateException(error); }
        } finally { if (connection != null) connection.disconnect(); }
        Log.i("REPACK_FIXTURE", event.toString());
    }
}
