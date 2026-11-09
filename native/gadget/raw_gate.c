#include <jni.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/syscall.h>

__attribute__((visibility("default"),noinline)) int repack_fixture_raw_gate(const char *path, uint64_t expected) {
    long fd = syscall(SYS_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) return 0;
    unsigned char buffer[8192]; long count; uint64_t actual = UINT64_C(14695981039346656037);
    while ((count = syscall(SYS_read, fd, buffer, sizeof(buffer))) > 0) {
        for (long i = 0; i < count; ++i) { actual ^= buffer[i]; actual *= UINT64_C(1099511628211); }
    }
    syscall(SYS_close, fd);
    return count == 0 && actual == expected;
}
JNIEXPORT jboolean JNICALL Java_dev_repack_fixture_identity_GadgetActivity_nativeGate(JNIEnv *env, jclass cls, jstring source, jlong expected) {
    (void)cls;
    const char *path = (*env)->GetStringUTFChars(env, source, 0);
    if (!path) return JNI_FALSE;
    int result = repack_fixture_raw_gate(path, (uint64_t)expected);
    (*env)->ReleaseStringUTFChars(env, source, path);
    return result ? JNI_TRUE : JNI_FALSE;
}
JNIEXPORT jint JNICALL Java_dev_repack_fixture_identity_GadgetActivity_nativeUnrelated(JNIEnv *env, jclass cls) {
    (void)env; (void)cls; return 42;
}
