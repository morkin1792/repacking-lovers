#include <jni.h>
#include <dlfcn.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

static int calls;
static int reject(int ok, void *ctx) { (void)ok; (void)ctx; calls++; return 0; }
static int reject_cert(void *ctx, void *arg) { (void)ctx; (void)arg; calls++; return 0; }

JNIEXPORT jstring JNICALL Java_dev_repack_fixture_expansion_ExpansionActivity_nativeProbe(
        JNIEnv *env, jclass cls, jstring library, jint port, jint variant) {
    (void)cls; char out[1024]; calls = 0;
    const char *name = (*env)->GetStringUTFChars(env, library, 0);
    void *handle = dlopen(name, RTLD_NOW | RTLD_LOCAL);
    (*env)->ReleaseStringUTFChars(env, library, name);
    if (!handle) return (*env)->NewStringUTF(env, "{\"error\":\"provider dlopen failed\"}");
#define FN(ret, name, args) ret (*name) args = (ret (*) args)dlsym(handle, #name); if (!name) { snprintf(out, sizeof(out), "{\"error\":\"missing %s\"}", #name); goto done; }
    FN(void *, TLS_client_method, (void));
    FN(void *, SSL_CTX_new, (const void *));
    FN(void, SSL_CTX_set_verify, (void *, int, int (*)(int, void *)));
    FN(void, SSL_CTX_set_cert_verify_callback, (void *, int (*)(void *, void *), void *));
    FN(void *, SSL_new, (void *));
    FN(int, SSL_set_fd, (void *, int));
    FN(int, SSL_connect, (void *));
    FN(long, SSL_get_verify_result, (const void *));
    FN(void *, SSL_get1_peer_certificate, (const void *));
    FN(int, SSL_write, (void *, const void *, int));
    FN(int, SSL_read, (void *, void *, int));
    FN(void, SSL_free, (void *));
    FN(void, X509_free, (void *));
    FN(void, SSL_CTX_free, (void *));
    void *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) { snprintf(out, sizeof(out), "{\"error\":\"SSL_CTX_new failed\"}"); goto done; }
    SSL_CTX_set_verify(ctx, 1, reject);
    if (variant == 1) SSL_CTX_set_cert_verify_callback(ctx, reject_cert, NULL);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct timeval timeout = {7, 0}; setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)); setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    if (fd < 0 || connect(fd, (struct sockaddr *)&address, sizeof(address))) { snprintf(out, sizeof(out), "{\"error\":\"local connect failed\"}"); if (fd >= 0) close(fd); SSL_CTX_free(ctx); goto done; }
    void *ssl = SSL_new(ctx); SSL_set_fd(ssl, fd);
    int connected = SSL_connect(ssl) == 1; long verify = SSL_get_verify_result(ssl);
    void *peer = connected ? SSL_get1_peer_certificate(ssl) : NULL; int payload = 0;
    if (connected) {
        const char request[] = "GET /native HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n"; char buf[1024];
        if (SSL_write(ssl, request, sizeof(request) - 1) > 0) { int n = SSL_read(ssl, buf, sizeof(buf) - 1); if (n > 0) { buf[n] = 0; payload = strstr(buf, " 200 ") != NULL; } }
    }
    snprintf(out, sizeof(out), "{\"connected\":%s,\"verify_result\":%ld,\"peer\":%s,\"payload\":%s,\"callback_calls\":%d}", connected ? "true" : "false", verify, peer ? "true" : "false", payload ? "true" : "false", calls);
    if (peer) X509_free(peer); SSL_free(ssl); close(fd); SSL_CTX_free(ctx);
done:
    // Keep the provider loaded until process exit: runtime cleanup must not
    // invalidate native TLS global state or retained JNI registrations.
    return (*env)->NewStringUTF(env, out);
}
