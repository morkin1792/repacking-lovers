package dev.repack.fixture.identity;

import android.app.Activity;
import android.os.Bundle;
import dev.repack.fixture.common.SigningProbe;

public final class ProbeActivity extends Activity {
    @Override
    public void onCreate(Bundle state) {
        super.onCreate(state);
        if ("contract".equals(getIntent().getStringExtra("scenario"))) dev.repack.fixture.common.ContractProbe.run(this, getIntent());
        else if ("cache-state".equals(getIntent().getStringExtra("scenario"))) dev.repack.fixture.common.CacheProbe.state(this, getIntent());
        else if ("process".equals(getIntent().getStringExtra("scenario"))) dev.repack.fixture.common.ProcessProbe.launch(this, getIntent());
        else if ("native-smoke".equals(getIntent().getStringExtra("scenario")) || "native-integrity".equals(getIntent().getStringExtra("scenario")) || "native-public".equals(getIntent().getStringExtra("scenario"))) dev.repack.fixture.common.NativeFileProbe.run(this, getIntent());
        else SigningProbe.run(this, getIntent());
    }
}
