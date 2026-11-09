package dev.repack.fixture.common;

import android.app.AppComponentFactory;
import android.app.Application;
import android.app.Activity;
import android.app.Service;
import android.content.Intent;
import android.content.BroadcastReceiver;
import android.content.ContentProvider;
import android.content.pm.ApplicationInfo;

/** Deliberately has no static fields or class initializer. */
public final class FixtureFactory extends AppComponentFactory {
    public FixtureFactory() {
        SigningProbe.marker("factory-constructor");
    }

    @Override
    public ClassLoader instantiateClassLoader(ClassLoader loader, ApplicationInfo info) {
        SigningProbe.marker("factory-classloader-entry");
        return super.instantiateClassLoader(loader, info);
    }

    @Override
    public Application instantiateApplication(ClassLoader loader, String name)
            throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        SigningProbe.marker("factory-application-entry");
        return super.instantiateApplication(loader, name);
    }

    @Override
    public Activity instantiateActivity(ClassLoader loader, String name, Intent intent)
            throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        SigningProbe.marker("factory-activity-entry");
        return super.instantiateActivity(loader, name, intent);
    }

    @Override
    public ContentProvider instantiateProvider(ClassLoader loader, String name)
            throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        SigningProbe.marker("factory-provider-entry");
        return super.instantiateProvider(loader, name);
    }

    @Override
    public BroadcastReceiver instantiateReceiver(ClassLoader loader, String name, Intent intent)
            throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        SigningProbe.marker("factory-receiver-entry");
        return super.instantiateReceiver(loader, name, intent);
    }

    @Override
    public Service instantiateService(ClassLoader loader, String name, Intent intent)
            throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        SigningProbe.marker("factory-service-entry");
        return super.instantiateService(loader, name, intent);
    }
}
