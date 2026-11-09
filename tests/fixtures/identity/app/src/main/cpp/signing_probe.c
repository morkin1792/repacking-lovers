#include <jni.h>

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)vm; (void)reserved; return JNI_VERSION_1_6;
}

JNIEXPORT jobject JNICALL Java_dev_repack_fixture_common_NativeProbe_query(
        JNIEnv *env, jclass owner, jobject context, jstring package_name, jint flags) {
    (void)owner;
    jclass context_class = (*env)->FindClass(env, "android/content/Context");
    if (context_class == NULL) return NULL;
    jmethodID get_manager = (*env)->GetMethodID(env, context_class, "getPackageManager",
            "()Landroid/content/pm/PackageManager;");
    if (get_manager == NULL) return NULL;
    jobject manager = (*env)->CallObjectMethod(env, context, get_manager);
    if ((*env)->ExceptionCheck(env) || manager == NULL) return NULL;
    jclass manager_class = (*env)->FindClass(env, "android/content/pm/PackageManager");
    if (manager_class == NULL) return NULL;
    jmethodID query = (*env)->GetMethodID(env, manager_class, "getPackageInfo",
            "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
    if (query == NULL) return NULL;
    /* Leave a real Java exception pending: the JNI bridge rethrows the original cause. */
    return (*env)->CallObjectMethod(env, manager, query, package_name, flags);
}

JNIEXPORT jstring JNICALL Java_dev_repack_fixture_common_NativeProbe_abi(JNIEnv *env, jclass owner) {
    (void)owner; return (*env)->NewStringUTF(env, REPACK_ABI);
}
