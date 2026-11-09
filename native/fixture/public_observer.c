#define _LARGEFILE64_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <inttypes.h>
#include <jni.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void *loaded[2];
static const char *const names[2] = {"librepack_io_early.so", "librepack_io_late.so"};
static int slot(const char *name) {
  for (int n = 0; n < 2; n++) if (!strcmp(name, names[n])) return n;
  return -1;
}
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
  (void)reserved; JNIEnv *env = NULL;
  return vm && (*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) == JNI_OK && env ? JNI_VERSION_1_6 : JNI_ERR;
}
JNIEXPORT jbyteArray JNICALL Java_dev_repack_fixture_common_NativeFileProbe_readImported(JNIEnv *env, jclass type, jstring source, jstring library) {
  (void)type; const char *path = (*env)->GetStringUTFChars(env, source, NULL);
  if (!path) return NULL;
  const char *name = (*env)->GetStringUTFChars(env, library, NULL);
  if (!name) { (*env)->ReleaseStringUTFChars(env, source, path); return NULL; }
  int index = slot(name), fd = -1; unsigned char *bytes = NULL; jbyteArray result = NULL;
  const char *previous = getenv("REPACK_FIXTURE_APK"); char *saved = previous ? strdup(previous) : NULL;
  if (index < 0 || (previous && !saved) || setenv("REPACK_FIXTURE_APK", path, 1)) goto done;
  if (!loaded[index]) loaded[index] = dlopen(name, RTLD_NOW | RTLD_LOCAL);
  if (saved) setenv("REPACK_FIXTURE_APK", saved, 1); else unsetenv("REPACK_FIXTURE_APK");
  if (!loaded[index]) goto done;
  int (*open_import)(const char *) = (int (*)(const char *))dlsym(loaded[index], "repack_io_open");
  if (!open_import || (fd = open_import(path)) < 0) goto done;
  struct stat metadata;
  if (fstat(fd, &metadata) || metadata.st_size <= 0 || metadata.st_size > 8388608) goto done;
  size_t size = (size_t)metadata.st_size, used = 0; bytes = malloc(size);
  if (!bytes) goto done;
  while (used < size) { ssize_t count = read(fd, bytes + used, size - used); if (count <= 0) goto done; used += (size_t)count; }
  result = (*env)->NewByteArray(env, (jsize)size);
  if (result) (*env)->SetByteArrayRegion(env, result, 0, (jsize)size, (const jbyte *)bytes);
done:
  free(saved); free(bytes); if (fd >= 0) close(fd);
  (*env)->ReleaseStringUTFChars(env, source, path); (*env)->ReleaseStringUTFChars(env, library, name);
  return result;
}
JNIEXPORT jstring JNICALL Java_dev_repack_fixture_common_NativeFileProbe_constructorObservation(JNIEnv *env, jclass type, jstring library) {
  (void)type; const char *name = (*env)->GetStringUTFChars(env, library, NULL);
  if (!name) return NULL;
  int index = slot(name); int64_t bytes = -1; uint64_t hash = 0;
  if (index >= 0 && loaded[index]) {
    void (*probe)(int64_t *, uint64_t *) = (void (*)(int64_t *, uint64_t *))dlsym(loaded[index], "repack_io_constructor");
    if (probe) probe(&bytes, &hash);
  }
  (*env)->ReleaseStringUTFChars(env, library, name);
  char value[160]; snprintf(value, sizeof(value), "{\"bytes\":%" PRId64 ",\"fnv64\":\"%016" PRIx64 "\"}", bytes, hash);
  return (*env)->NewStringUTF(env, value);
}
