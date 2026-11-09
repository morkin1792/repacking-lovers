#define _LARGEFILE64_SOURCE
#include "io_fixture.h"
#include "bytehook.h"
#if defined(__arm__) || defined(__aarch64__)
#include "shadowhook.h"
#endif
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <jni.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

enum { STAGES = 5 };
static const char *const libraries[2] = {"librepack_io_early.so", "librepack_io_late.so"};
#include "../core/file_imports.h"
static unsigned pre_load, post_load;
static int post_result = -99;
static int owned_jni_loaded;
static char vm_implementation[1024];
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
  (void)reserved; JNIEnv *env = NULL;
  if (!vm || (*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK || !env) return JNI_ERR;
  Dl_info implementation;
  if (dladdr((const void *)(*vm)->GetEnv, &implementation) && implementation.dli_fname)
    snprintf(vm_implementation, sizeof(vm_implementation), "%s", implementation.dli_fname);
  owned_jni_loaded = 1;
  return JNI_VERSION_1_6;
}
static void pre(const char *filename, void *arg) {
  (void)arg; if (filename && strstr(filename, libraries[1])) pre_load++;
}
static void post(const char *filename, int result, void *arg) {
  (void)arg; if (filename && strstr(filename, libraries[1])) { post_load++; post_result = result; }
}
static char output[65536];
static size_t used;
static int overflow;
static void append(const char *format, ...) {
  if (overflow) return;
  va_list args; va_start(args, format); int count = vsnprintf(output + used, sizeof(output) - used, format, args); va_end(args);
  if (count < 0 || (size_t)count >= sizeof(output) - used) { overflow = 1; return; }
  used += (size_t)count;
}
static void json_string(const char *value) {
  append("\"");
  for (const unsigned char *cursor = (const unsigned char *)value; *cursor; cursor++) {
    if (*cursor == '"' || *cursor == '\\') append("\\%c", *cursor);
    else if (*cursor < 32) append("\\u%04x", *cursor);
    else append("%c", *cursor);
  }
  append("\"");
}
static void rows_json(const io_result *rows) {
  append("[");
  for (int index = 0; index < IO_PATHS; index++) {
    const io_result *r = &rows[index];
    char digest[65], mapped_digest[65]; for (int n = 0; n < 32; n++) {
      snprintf(digest + n * 2, 3, "%02x", r->sha256[n]);
      snprintf(mapped_digest + n * 2, 3, "%02x", r->mmap_sha256[n]);
    }
    append("%s{\"path\":\"%s\",\"ok\":%d,\"errno\":%d,\"bytes\":%" PRId64 ",\"fnv64\":\"%016" PRIx64
      "\",\"stat_size\":%" PRId64 ",\"stat64_size\":%" PRId64 ",\"fd_size\":%" PRId64 ",\"fd64_size\":%" PRId64
      ",\"readlink_source\":%d,\"readlinkat_source\":%d,\"readlink_retained\":%d,\"readlinkat_retained\":%d,\"sha256\":\"%s\",\"readlink_target\":\"%s\",\"offsets_ok\":%d,\"duplicate_size\":%" PRId64 ",\"duplicate_retained\":%d,\"mmap_ok\":%d,\"mmap_errno\":%d,\"mmap_sha256\":\"%s\"}", index ? "," : "", io_names[index], r->ok, r->error,
      r->bytes, r->hash, r->path_size, r->path64_size, r->fd_size, r->fd64_size, r->link_ok, r->linkat_ok,
      r->link_retained, r->linkat_retained, digest, r->link_target, r->offsets_ok, r->duplicate_size, r->duplicate_retained,
      r->mmap_ok, r->mmap_error, mapped_digest);
  }
  append("]");
}
static void counts_json(const unsigned *counts) {
  append("{"); for (int n = 0; n < SYMBOLS; n++) append("%s\"%s\":%u", n ? "," : "", symbols[n], counts[n]); append("}");
}
static int capture_runtime(JNIEnv *env, jclass type, char *out, size_t size, unsigned *delta) {
  unsigned before[SYMBOLS]; memcpy(before, hits, sizeof(before));
  jmethodID method = (*env)->GetStaticMethodID(env, type, "activeRuntime", "()Ljava/lang/String;");
  if (!method) return -1;
  jstring value = (jstring)(*env)->CallStaticObjectMethod(env, type, method);
  if ((*env)->ExceptionCheck(env) || !value) return -1;
  const char *text = (*env)->GetStringUTFChars(env, value, NULL);
  if (!text) return -1;
  int overflowed = strlen(text) >= size;
  if (!overflowed) strcpy(out, text);
  (*env)->ReleaseStringUTFChars(env, value, text); (*env)->DeleteLocalRef(env, value);
  for (int n = 0; n < SYMBOLS; n++) delta[n] = hits[n] - before[n];
  return overflowed ? -1 : 0;
}
JNIEXPORT jstring JNICALL Java_dev_repack_fixture_common_NativeFileProbe_smoke(JNIEnv *env, jclass type, jstring source, jstring retained) {
  const char *path = (*env)->GetStringUTFChars(env, source, NULL);
  if (!path) return NULL;
  source_name = strdup(path); retained_name = NULL;
  if (retained) {
    const char *value = (*env)->GetStringUTFChars(env, retained, NULL);
    if (!value) { free((void *)source_name); source_name = NULL; (*env)->ReleaseStringUTFChars(env, source, path); return NULL; }
    retained_name = strdup(value); (*env)->ReleaseStringUTFChars(env, retained, value);
  }
  used = 0; overflow = 0;
  int preopened = open(path, O_RDONLY);
  void *early = NULL, *late = NULL; int callbacks_registered = 0;
  char runtime[8192] = "{}", runtime_late[8192] = "{}";
  unsigned runtime_delta[SYMBOLS] = {0}, runtime_late_delta[SYMBOLS] = {0};
  int shadow_status = 0;
#if defined(__arm__) || defined(__aarch64__)
  shadow_status = shadowhook_init(SHADOWHOOK_MODE_SHARED, false);
#endif
  int init_status = bytehook_init(BYTEHOOK_MODE_AUTOMATIC, false);
  early = dlopen(libraries[0], RTLD_NOW | RTLD_LOCAL);
  io_probe_fn early_probe = early ? (io_probe_fn)dlsym(early, "repack_io_probe") : NULL;
  if (shadow_status || init_status || !early_probe) {
    append("{\"error\":\"init-or-early-load\",\"shadow_status\":%d,\"init_status\":%d}", shadow_status, init_status);
    goto done;
  }
  io_result results[STAGES][IO_PATHS]; unsigned counters[STAGES][SYMBOLS], constructor_hits[SYMBOLS];
#define PROBE_PHASE(FUNCTION, INDEX) do { \
  FUNCTION(env, path, retained_name, preopened, results[INDEX]); \
  if ((*env)->ExceptionCheck(env)) goto done; \
} while (0)
  memset(hits, 0, sizeof(hits)); PROBE_PHASE(early_probe, 0); memcpy(counters[0], hits, sizeof(hits));
  hook_one(0, 3); memset(hits, 0, sizeof(hits)); PROBE_PHASE(early_probe, 1); memcpy(counters[1], hits, sizeof(hits));
  for (int n = 0; n < SYMBOLS; n++) { if (n != 3) hook_one(0, n); hook_one(1, n); }
  memset(hits, 0, sizeof(hits)); PROBE_PHASE(early_probe, 2); memcpy(counters[2], hits, sizeof(hits));
  if (capture_runtime(env, type, runtime, sizeof(runtime), runtime_delta)) { append("{\"error\":\"runtime-observation-failed\"}"); goto done; }
  bytehook_add_dlopen_callback(pre, post, NULL);
  callbacks_registered = 1;
  memset(hits, 0, sizeof(hits));
  late = dlopen(libraries[1], RTLD_NOW | RTLD_LOCAL);
  memcpy(constructor_hits, hits, sizeof(hits));
  io_probe_fn late_probe = late ? (io_probe_fn)dlsym(late, "repack_io_probe") : NULL;
  if (!late_probe) { append("{\"error\":\"late-load\"}"); goto done; }
  memset(hits, 0, sizeof(hits)); PROBE_PHASE(late_probe, 3); memcpy(counters[3], hits, sizeof(hits));
  if (capture_runtime(env, type, runtime_late, sizeof(runtime_late), runtime_late_delta)) { append("{\"error\":\"delayed-runtime-observation-failed\"}"); goto done; }
  int unhook[TASKS]; for (int n = 0; n < TASKS; n++) {
    unhook[n] = tasks[n].stub ? bytehook_unhook(tasks[n].stub) : -99; tasks[n].stub = NULL;
  }
  bytehook_del_dlopen_callback(pre, post, NULL);
  callbacks_registered = 0;
  memset(hits, 0, sizeof(hits)); PROBE_PHASE(late_probe, 4); memcpy(counters[4], hits, sizeof(hits));
  const char *private_path = vm_implementation[0] ? vm_implementation : sizeof(void *) == 8 ? "/system/lib64/libart.so" : "/system/lib/libart.so";
  int private_path_exists = access(private_path, F_OK) == 0;
  (void)dlerror(); void *private_platform = dlopen(private_path, RTLD_NOW | RTLD_LOCAL);
  const char *load_error = dlerror(); char private_error[1024]; snprintf(private_error, sizeof(private_error), "%s", load_error ? load_error : "");
  int namespace_accessible = private_platform != NULL; if (private_platform) dlclose(private_platform);
  append("{\"init_status\":%d,\"shadow_status\":%d,\"owned_jni_loaded\":%d,\"pointer_bits\":%zu,\"stages\":[", init_status, shadow_status, owned_jni_loaded, sizeof(void *) * 8);
  for (int stage = 0; stage < STAGES; stage++) {
    append("%s{\"stage\":%d,\"hits\":", stage ? "," : "", stage); counts_json(counters[stage]);
    append(",\"rows\":"); rows_json(results[stage]); append("}");
  }
  append("],\"tasks\":[");
  for (int n = 0; n < TASKS; n++) append("%s{\"library\":\"%s\",\"symbol\":\"%s\",\"status\":%d,\"unhook\":%d}",
      n ? "," : "", tasks[n].library ? "late" : "early", symbols[tasks[n].symbol], tasks[n].status, unhook[n]);
  append("],\"late_constructor_hits\":"); counts_json(constructor_hits);
  append(",\"pre_dlopen\":%u,\"post_dlopen\":%u,\"post_result\":%d,\"private_platform_library_accessible\":%d,\"active_runtime\":%s,\"runtime_stage\":2,\"runtime_import_delta\":",
      pre_load, post_load, post_result, namespace_accessible, runtime);
  counts_json(runtime_delta);
  append(",\"runtime_after_delayed_load\":%s,\"runtime_after_stage\":3,\"runtime_after_import_delta\":", runtime_late);
  counts_json(runtime_late_delta);
  append(",\"private_platform_path\":"); json_string(private_path);
  append(",\"private_platform_path_exists\":%d,\"private_platform_error\":", private_path_exists); json_string(private_error); append("}");
done:
  if (callbacks_registered) bytehook_del_dlopen_callback(pre, post, NULL);
  for (int n = 0; n < TASKS; n++) if (tasks[n].stub) { bytehook_unhook(tasks[n].stub); tasks[n].stub = NULL; }
  if (late) dlclose(late);
  if (early) dlclose(early);
  if (preopened >= 0) close(preopened);
  free((void *)source_name); free((void *)retained_name); source_name = NULL; retained_name = NULL;
  (*env)->ReleaseStringUTFChars(env, source, path);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (overflow) return (*env)->NewStringUTF(env, "{\"error\":\"output-overflow\"}");
  return (*env)->NewStringUTF(env, output);
}
