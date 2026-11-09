package io.flutter.embedding.engine.plugins;
public interface FlutterPlugin {
    void onAttachedToEngine(FlutterPluginBinding binding);
    void onDetachedFromEngine(FlutterPluginBinding binding);
    final class FlutterPluginBinding {
        public Object getBinaryMessenger() { return null; }
        public Engine getFlutterEngine() { return new Engine(); }
    }
    final class Engine { public Object getDartExecutor() { return null; } }
}
