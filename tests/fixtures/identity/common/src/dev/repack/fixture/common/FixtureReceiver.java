package dev.repack.fixture.common;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

public final class FixtureReceiver extends BroadcastReceiver {
    @Override public void onReceive(Context context, Intent intent) {
        SigningProbe.marker("receiver-onReceive:" + intent.getStringExtra("token"));
    }
}
