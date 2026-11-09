package dev.repack.fixture.other;

import android.app.Activity;
import android.os.Bundle;
import dev.repack.fixture.common.SigningProbe;

public final class ProbeActivity extends Activity {
    @Override
    public void onCreate(Bundle state) {
        super.onCreate(state);
        if ("contract".equals(getIntent().getStringExtra("scenario"))) dev.repack.fixture.common.ContractProbe.run(this, getIntent());
        else SigningProbe.run(this, getIntent());
    }
}
