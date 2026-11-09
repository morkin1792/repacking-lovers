package dev.repack.fixture.common;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import org.json.JSONObject;

public final class NetworkReceiver extends BroadcastReceiver {
    @Override public void onReceive(final Context context, Intent intent) {
        final JSONObject config;
        try { config = new JSONObject(intent.getStringExtra("network_json")); }
        catch (Exception error) { throw new IllegalArgumentException(error); }
        final PendingResult pending = goAsync();
        new Thread(new Runnable() {
            public void run() {
                try { NetworkProbe.runRequest(context, config); }
                finally { pending.finish(); }
            }
        }, "repack-fixture-followup").start();
    }
}
