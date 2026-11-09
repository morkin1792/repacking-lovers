package dev.repack.shim;

import android.app.Activity;
import android.app.AppComponentFactory;
import android.app.Application;
import android.app.Service;
import android.content.BroadcastReceiver;
import android.content.ContentProvider;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import java.lang.reflect.InvocationTargetException;

/** Composition preserves final original factories and their component/loader contracts. */
public final class RepackFactory extends AppComponentFactory {
    private AppComponentFactory delegate;

    public RepackFactory() {
        Bootstrap.initEarly();
    }

    private synchronized AppComponentFactory delegate(ClassLoader loader) {
        if (delegate != null) return delegate;
        try {
            if (RepackConfig.ORIGINAL_FACTORY.length() == 0) {
                delegate = new AppComponentFactory();
            } else {
                if (RepackConfig.ORIGINAL_FACTORY.equals(getClass().getName())) {
                    throw new IllegalStateException("Already patched factory");
                }
                delegate = (AppComponentFactory) Class.forName(RepackConfig.ORIGINAL_FACTORY, true, loader)
                        .getDeclaredConstructor().newInstance();
            }
            return delegate;
        } catch (InvocationTargetException failure) {
            return RepackFactory.<RuntimeException, AppComponentFactory>rethrow(failure.getCause());
        } catch (ReflectiveOperationException failure) {
            throw new IllegalStateException("Cannot construct original component factory", failure);
        }
    }

    @SuppressWarnings("unchecked")
    private static <E extends Throwable, T> T rethrow(Throwable failure) throws E {
        throw (E) failure;
    }

    @Override
    public ClassLoader instantiateClassLoader(ClassLoader loader, ApplicationInfo info) {
        Bootstrap.initEarly();
        Bootstrap.nativeClassLoader(info);
        ClassLoader result = delegate(loader).instantiateClassLoader(loader, info);
        Bootstrap.classLoader(info, loader, result);
        return result;
    }

    @Override
    public Application instantiateApplication(ClassLoader loader, String name)
            throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        Bootstrap.initEarly();
        Bootstrap.initLate();
        Application application = delegate(loader).instantiateApplication(loader, name);
        Bootstrap.applicationCreated(application);
        return application;
    }

    @Override
    public Activity instantiateActivity(ClassLoader loader, String name, Intent intent)
            throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        return delegate(loader).instantiateActivity(loader, name, intent);
    }

    @Override
    public ContentProvider instantiateProvider(ClassLoader loader, String name)
            throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        return delegate(loader).instantiateProvider(loader, name);
    }

    @Override
    public BroadcastReceiver instantiateReceiver(ClassLoader loader, String name, Intent intent)
            throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        return delegate(loader).instantiateReceiver(loader, name, intent);
    }

    @Override
    public Service instantiateService(ClassLoader loader, String name, Intent intent)
            throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        return delegate(loader).instantiateService(loader, name, intent);
    }
}
