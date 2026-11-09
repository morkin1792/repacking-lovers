package io.flutter.plugin.common;
public final class MethodChannel {
    public MethodChannel(Object messenger, String name) {}
    public void setMethodCallHandler(MethodCallHandler handler) {}
    public interface MethodCallHandler { void onMethodCall(MethodCall call, Result result); }
    public interface Result {
        void success(Object result);
        void error(String code, String message, Object details);
        void notImplemented();
    }
}
