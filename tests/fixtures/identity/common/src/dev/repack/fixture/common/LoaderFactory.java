package dev.repack.fixture.common;

import android.app.AppComponentFactory;
import android.app.Application;
import android.content.pm.ApplicationInfo;

public final class LoaderFactory extends AppComponentFactory {
    private ClassLoader selected;

    @Override
    public ClassLoader instantiateClassLoader(ClassLoader original, ApplicationInfo info) {
        selected = new ClassLoader(original) {};
        SigningProbe.marker("custom-loader-created");
        return selected;
    }

    @Override
    public Application instantiateApplication(ClassLoader loader, String name)
            throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        if (loader != selected) throw new IllegalStateException("Custom loader delegation changed");
        SigningProbe.marker("custom-loader-retained");
        return super.instantiateApplication(loader, name);
    }
}
