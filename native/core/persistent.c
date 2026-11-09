#define _LARGEFILE64_SOURCE
#include <jni.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#if defined(__arm__) || defined(__aarch64__)
#include "shadowhook.h"
#endif
static const char *libraries[2];
#include "file_imports.h"

static int armed, caller_count, shadow_status = -1, hook_status = -1;
static char result[8192];
static size_t length;
static int overflow;
static void add(const char *format, ...) {
  if (overflow) return;
  va_list args; va_start(args, format);
  int count = vsnprintf(result + length, sizeof(result) - length, format, args); va_end(args);
  if (count < 0 || (size_t)count >= sizeof(result) - length) { overflow = 1; return; }
  length += (size_t)count;
}
static jstring snapshot(JNIEnv *env) {
  length = 0; overflow = 0;
  int matched = 0, pending = 0, missing = 0;
  for (int n = 0; n < caller_count * SYMBOLS; n++) {
    int status = __atomic_load_n(&tasks[n].status, __ATOMIC_ACQUIRE);
    if (status == BYTEHOOK_STATUS_CODE_OK) matched++;
    if (status == -99) pending++;
    if (status == BYTEHOOK_STATUS_CODE_NOSYM) missing++;
  }
  add("{\"schema_version\":1,\"pid\":%d,\"armed\":%s,\"pointer_bits\":%zu,\"shadow_status\":%d,\"hook_status\":%d,\"registered_tasks\":%d,\"matched_imports\":%d,\"pending_tasks\":%d,\"missing_imports\":%d,\"hits\":{",
      getpid(), armed ? "true" : "false", sizeof(void *) * 8, shadow_status, hook_status,
      armed ? caller_count * SYMBOLS : 0, matched, pending, missing);
  for (int n = 0; n < SYMBOLS; n++) add("%s\"%s\":%u", n ? "," : "", symbols[n], __atomic_load_n(&hits[n], __ATOMIC_RELAXED));
  add("},\"tasks\":[");
  for (int n = 0; n < caller_count * SYMBOLS; n++)
    add("%s{\"caller\":\"%s\",\"symbol\":\"%s\",\"status\":%d}", n ? "," : "",
        libraries[tasks[n].library], symbols[tasks[n].symbol], __atomic_load_n(&tasks[n].status, __ATOMIC_ACQUIRE));
  add("]}");
  return (*env)->NewStringUTF(env, overflow ? "{\"armed\":false,\"error\":\"snapshot-overflow\"}" : result);
}
static char *copy_string(JNIEnv *env, jstring value) {
  if (!value) return NULL;
  const char *text = (*env)->GetStringUTFChars(env, value, NULL);
  if (!text) return NULL;
  char *copy = strdup(text); (*env)->ReleaseStringUTFChars(env, value, text); return copy;
}
static int valid_caller(const char *name) {
  if (!name || strlen(name) < 7 || strlen(name) > 128 || strncmp(name, "lib", 3) || strcmp(name + strlen(name) - 3, ".so")) return 0;
  for (const unsigned char *p = (const unsigned char *)name; *p; p++)
    if (!( (*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9') || *p == '.' || *p == '_' || *p == '-')) return 0;
  return 1;
}
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
  (void)reserved; JNIEnv *env = NULL;
  return vm && (*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) == JNI_OK && env ? JNI_VERSION_1_6 : JNI_ERR;
}
JNIEXPORT jstring JNICALL Java_dev_repack_shim_NativeIntegrity_start(JNIEnv *env, jclass type,
    jstring source, jstring original, jobjectArray callers) {
  (void)type;
  if (armed) return snapshot(env);
  if (!callers || (*env)->GetArrayLength(env, callers) < 1 || (*env)->GetArrayLength(env, callers) > 2)
    return (*env)->NewStringUTF(env, "{\"armed\":false,\"error\":\"caller-count\"}");
  source_name = copy_string(env, source); retained_name = copy_string(env, original);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (!source_name || !retained_name || source_name[0] != '/' || retained_name[0] != '/')
    return (*env)->NewStringUTF(env, "{\"armed\":false,\"error\":\"invalid-original-paths\"}");
  caller_count = (*env)->GetArrayLength(env, callers);
  for (int n = 0; n < caller_count; n++) {
    jstring name = (jstring)(*env)->GetObjectArrayElement(env, callers, n);
    libraries[n] = copy_string(env, name); (*env)->DeleteLocalRef(env, name);
    if ((*env)->ExceptionCheck(env)) return NULL;
    if (!valid_caller(libraries[n])) { caller_count = 0; return (*env)->NewStringUTF(env, "{\"armed\":false,\"error\":\"invalid-caller\"}"); }
  }
  for (int n = 0; n < caller_count * SYMBOLS; n++) {
    tasks[n].library = n / SYMBOLS; tasks[n].symbol = n % SYMBOLS; tasks[n].status = -99;
  }
  shadow_status = 0;
#if defined(__arm__) || defined(__aarch64__)
  shadow_status = shadowhook_init(SHADOWHOOK_MODE_SHARED, false);
#endif
  hook_status = bytehook_init(BYTEHOOK_MODE_AUTOMATIC, false);
  if (shadow_status || hook_status || bytehook_get_mode() != BYTEHOOK_MODE_AUTOMATIC) return snapshot(env);
  for (int library = 0; library < caller_count; library++) for (int symbol = 0; symbol < SYMBOLS; symbol++) {
    hook_one(library, symbol);
    if (!tasks[library * SYMBOLS + symbol].stub) {
      for (int n = 0; n < TASKS; n++) if (tasks[n].stub) { bytehook_unhook(tasks[n].stub); tasks[n].stub = NULL; }
      return snapshot(env);
    }
  }
  armed = 1; return snapshot(env);
}
JNIEXPORT jstring JNICALL Java_dev_repack_shim_NativeIntegrity_nativeSnapshot(JNIEnv *env, jclass type) {
  (void)type; return snapshot(env);
}
