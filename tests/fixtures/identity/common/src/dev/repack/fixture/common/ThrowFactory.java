package dev.repack.fixture.common;

import android.app.Activity;
import android.app.AppComponentFactory;
import android.content.Intent;

public final class ThrowFactory extends AppComponentFactory {
    @Override
    public Activity instantiateActivity(ClassLoader loader, String name, Intent intent)
            throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        if (name.endsWith(".FailureActivity")) {
            SigningProbe.marker("factory-delegate-failure:" + intent.getStringExtra("factory_failure_token"));
            throw new IllegalAccessException("fixture-delegate-contract");
        }
        return super.instantiateActivity(loader, name, intent);
    }
}
