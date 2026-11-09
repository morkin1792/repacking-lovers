package dev.repack.shim;

import android.app.Application;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.Build;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.SocketAddress;
import java.net.URI;
import java.util.Collections;
import java.util.List;
import org.json.JSONObject;

/** Only implicit HTTP(S) proxy selection is covered. No direct retry is supplied. */
final class Route {
    private static ProxySelector selector;
    private static BroadcastReceiver receiver;

    private static void log(String event, String phase, String reason, boolean published, Throwable error) {
        try {
            JSONObject details = new JSONObject();
            details.put("capability", "routing");
            details.put("reason", reason);
            details.put("published", published);
            details.put("selector_class", ProxySelector.getDefault() == null ? JSONObject.NULL
                    : ProxySelector.getDefault().getClass().getName());
            details.put("http_proxy_host", System.getProperty("http.proxyHost", ""));
            details.put("http_proxy_port", System.getProperty("http.proxyPort", ""));
            Bootstrap.event(event, phase, details, error);
        } catch (Exception failure) { throw new IllegalStateException(failure); }
    }

    static synchronized void install(String reason) {
        if (selector == null) {
            final ProxySelector previous = ProxySelector.getDefault();
            final List<Proxy> only = Collections.singletonList(new Proxy(Proxy.Type.HTTP,
                    new InetSocketAddress(RepackConfig.PROXY_HOST, RepackConfig.PROXY_PORT)));
            selector = new ProxySelector() {
                @Override public List<Proxy> select(URI uri) {
                    if (uri == null) throw new IllegalArgumentException("Null URI");
                    if ("http".equalsIgnoreCase(uri.getScheme()) || "https".equalsIgnoreCase(uri.getScheme())) {
                        return only;
                    }
                    return previous == null ? Collections.singletonList(Proxy.NO_PROXY) : previous.select(uri);
                }
                @Override public void connectFailed(URI uri, SocketAddress address, IOException failure) {
                    log("failure", "query", "connectFailed", ProxySelector.getDefault() == this, failure);
                }
            };
        }
        ProxySelector.setDefault(selector);
        for (String scheme : new String[] {"http", "https"}) {
            System.setProperty(scheme + ".proxyHost", RepackConfig.PROXY_HOST);
            System.setProperty(scheme + ".proxyPort", Integer.toString(RepackConfig.PROXY_PORT));
        }
        log("complete", "initLate", reason, ProxySelector.getDefault() == selector, null);
    }

    static synchronized void register(Application application) {
        if (receiver != null) return;
        receiver = new BroadcastReceiver() {
            @Override public void onReceive(Context context, Intent intent) {
                if (android.net.Proxy.PROXY_CHANGE_ACTION.equals(intent.getAction())) install("proxy-change");
            }
        };
        IntentFilter filter = new IntentFilter(android.net.Proxy.PROXY_CHANGE_ACTION);
        if (Build.VERSION.SDK_INT >= 33) application.registerReceiver(receiver, filter, Context.RECEIVER_EXPORTED);
        else application.registerReceiver(receiver, filter);
        log("complete", "context", "receiver-registered", ProxySelector.getDefault() == selector, null);
    }
}
