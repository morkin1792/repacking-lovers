package dev.repack.fixture.common;

import android.app.Application;
import android.content.Context;

public final class FixtureApplication extends Application {
    @Override
    protected void attachBaseContext(Context context) {
        super.attachBaseContext(context);
        SigningProbe.marker("application-attach");
    }

    @Override
    public void onCreate() {
        super.onCreate();
        SigningProbe.marker("application-onCreate");
        CryptoProbe.fromAsset(this);
        NetworkProbe.fromAsset(this);
    }
}
