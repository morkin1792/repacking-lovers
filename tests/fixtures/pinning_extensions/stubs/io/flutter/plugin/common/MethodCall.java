package io.flutter.plugin.common;
public final class MethodCall {
    public final String method;
    public final Object arguments;
    public MethodCall(String method, Object arguments) { this.method = method; this.arguments = arguments; }
}
