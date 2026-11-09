#define _LARGEFILE64_SOURCE
#include "io_fixture.h"
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

extern int __open_2(const char *, int);
extern int __openat_2(int, const char *, int);
static int64_t constructor_bytes;
static uint64_t constructor_hash;

__attribute__((constructor)) static void constructor_read(void) {
  const char *apk = getenv("REPACK_FIXTURE_APK");
  int fd = open(apk ? apk : "/proc/self/cmdline", O_RDONLY);
  if (fd >= 0) {
    if (!apk) { char value; (void)read(fd, &value, 1); }
    else {
      unsigned char buffer[8192]; ssize_t count; constructor_hash = UINT64_C(14695981039346656037);
      while ((count = read(fd, buffer, sizeof(buffer))) > 0) {
        constructor_bytes += count;
        for (ssize_t n = 0; n < count; n++) constructor_hash = (constructor_hash ^ buffer[n]) * UINT64_C(1099511628211);
      }
    }
    close(fd);
  }
}
__attribute__((visibility("default"))) int repack_io_open(const char *path) { return open(path, O_RDONLY); }
__attribute__((visibility("default"))) void repack_io_constructor(int64_t *bytes, uint64_t *hash) {
  *bytes = constructor_bytes; *hash = constructor_hash;
}

__attribute__((visibility("default"))) void repack_io_probe(JNIEnv *env, const char *path, const char *retained, int preopened, io_result *rows) {
  jclass digest_class = (*env)->FindClass(env, "java/security/MessageDigest");
  if (!digest_class) return;
  jmethodID factory = (*env)->GetStaticMethodID(env, digest_class, "getInstance", "(Ljava/lang/String;)Ljava/security/MessageDigest;");
  jmethodID update = (*env)->GetMethodID(env, digest_class, "update", "([BII)V");
  jmethodID finish = (*env)->GetMethodID(env, digest_class, "digest", "()[B");
  jstring algorithm = (*env)->NewStringUTF(env, "SHA-256");
  jbyteArray digest_buffer = (*env)->NewByteArray(env, 8192);
  if (!factory || !update || !finish || !algorithm || !digest_buffer) return;
  for (int index = 0; index < IO_PATHS; index++) {
    io_result *row = &rows[index]; memset(row, 0, sizeof(*row));
    FILE *file = NULL; int fd = -1; errno = 0;
    switch (index) {
      case 0: fd = open(path, O_RDONLY); break;
      case 1: fd = open64(path, O_RDONLY); break;
      case 2: fd = __open_2(path, O_RDONLY); break;
      case 3: fd = openat(AT_FDCWD, path, O_RDONLY); break;
      case 4: fd = openat64(AT_FDCWD, path, O_RDONLY); break;
      case 5: fd = __openat_2(AT_FDCWD, path, O_RDONLY); break;
      case 6: file = fopen(path, "rb"); fd = file ? fileno(file) : -1; break;
      case 7: file = fopen64(path, "rb"); fd = file ? fileno(file) : -1; break;
      case 8: fd = (int)syscall(__NR_openat, AT_FDCWD, path, O_RDONLY, 0); break;
      case 9: {
        int (*resolved)(const char *, int, ...) = (int (*)(const char *, int, ...))dlsym(RTLD_DEFAULT, "open");
        if (resolved) fd = resolved(path, O_RDONLY); break;
      }
      case 10: if (lseek(preopened, 0, SEEK_SET) == 0) fd = dup(preopened); break;
    }
    if (fd < 0) { row->error = errno; continue; }
    struct stat named, descriptor; struct stat64 named64, descriptor64;
    int metadata_ok = stat(path, &named) == 0 && stat64(path, &named64) == 0
        && fstat(fd, &descriptor) == 0 && fstat64(fd, &descriptor64) == 0;
    if (metadata_ok) {
      row->path_size = named.st_size; row->path64_size = named64.st_size;
      row->fd_size = descriptor.st_size; row->fd64_size = descriptor64.st_size;
    }
    char link_path[64], target[PATH_MAX]; snprintf(link_path, sizeof(link_path), "/proc/self/fd/%d", fd);
    ssize_t length = readlink(link_path, target, sizeof(target));
    if (length > 0 && length < (ssize_t)sizeof(row->link_target)) memcpy(row->link_target, target, (size_t)length);
    row->link_ok = length == (ssize_t)strlen(path) && memcmp(target, path, (size_t)length) == 0;
    row->link_retained = retained && length == (ssize_t)strlen(retained) && memcmp(target, retained, (size_t)length) == 0;
    length = readlinkat(AT_FDCWD, link_path, target, sizeof(target));
    row->linkat_ok = length == (ssize_t)strlen(path) && memcmp(target, path, (size_t)length) == 0;
    row->linkat_retained = retained && length == (ssize_t)strlen(retained) && memcmp(target, retained, (size_t)length) == 0;
    jobject digest = (*env)->CallStaticObjectMethod(env, digest_class, factory, algorithm);
    if ((*env)->ExceptionCheck(env) || !digest) { if (file) fclose(file); else close(fd); return; }
    unsigned char buffer[8192], prefix[8] = {0}; ssize_t count; row->hash = UINT64_C(14695981039346656037);
    while ((count = read(fd, buffer, sizeof(buffer))) > 0) {
      if (row->bytes == 0) memcpy(prefix, buffer, (size_t)count < sizeof(prefix) ? (size_t)count : sizeof(prefix));
      row->bytes += count;
      for (ssize_t n = 0; n < count; n++) row->hash = (row->hash ^ buffer[n]) * UINT64_C(1099511628211);
      (*env)->SetByteArrayRegion(env, digest_buffer, 0, (jsize)count, (const jbyte *)buffer);
      (*env)->CallVoidMethod(env, digest, update, digest_buffer, 0, (jint)count);
      if ((*env)->ExceptionCheck(env)) { if (file) fclose(file); else close(fd); return; }
    }
    row->ok = count == 0 && metadata_ok; row->error = count < 0 ? errno : 0;
    jbyteArray hash = (jbyteArray)(*env)->CallObjectMethod(env, digest, finish);
    if ((*env)->ExceptionCheck(env) || !hash) { if (file) fclose(file); else close(fd); return; }
    (*env)->GetByteArrayRegion(env, hash, 0, 32, (jbyte *)row->sha256);
    (*env)->DeleteLocalRef(env, hash);
    int duplicate = dup(fd); struct stat duplicated;
    ssize_t wanted = row->bytes < (int64_t)sizeof(prefix) ? (ssize_t)row->bytes : (ssize_t)sizeof(prefix);
    if (duplicate >= 0 && fstat(duplicate, &duplicated) == 0 && lseek(fd, 0, SEEK_SET) == 0) {
      row->duplicate_size = duplicated.st_size;
      ssize_t actual = read(duplicate, buffer, sizeof(prefix));
      int shared = actual == wanted && memcmp(buffer, prefix, (size_t)wanted) == 0
          && lseek(fd, 0, SEEK_CUR) == wanted && lseek(duplicate, 0, SEEK_CUR) == wanted;
      row->offsets_ok = shared && pread(fd, buffer, (size_t)wanted, 0) == wanted
          && memcmp(buffer, prefix, (size_t)wanted) == 0 && lseek(fd, 0, SEEK_CUR) == wanted;
      snprintf(link_path, sizeof(link_path), "/proc/self/fd/%d", duplicate);
      length = readlink(link_path, target, sizeof(target));
      row->duplicate_retained = retained && length == (ssize_t)strlen(retained) && memcmp(target, retained, (size_t)length) == 0;
    }
    if (duplicate >= 0) close(duplicate);
    void *mapping = row->bytes > 0 ? mmap(NULL, (size_t)row->bytes, PROT_READ, MAP_PRIVATE, fd, 0) : MAP_FAILED;
    if (mapping == MAP_FAILED) row->mmap_error = errno;
    else {
      for (int64_t offset = 0; offset < row->bytes; offset += (int64_t)sizeof(buffer)) {
        size_t remaining = (size_t)(row->bytes - offset), amount = remaining < sizeof(buffer) ? remaining : sizeof(buffer);
        (*env)->SetByteArrayRegion(env, digest_buffer, 0, (jsize)amount, (const jbyte *)mapping + offset);
        (*env)->CallVoidMethod(env, digest, update, digest_buffer, 0, (jint)amount);
        if ((*env)->ExceptionCheck(env)) { munmap(mapping, (size_t)row->bytes); if (file) fclose(file); else close(fd); return; }
      }
      hash = (jbyteArray)(*env)->CallObjectMethod(env, digest, finish);
      if ((*env)->ExceptionCheck(env) || !hash) { munmap(mapping, (size_t)row->bytes); if (file) fclose(file); else close(fd); return; }
      (*env)->GetByteArrayRegion(env, hash, 0, 32, (jbyte *)row->mmap_sha256);
      (*env)->DeleteLocalRef(env, hash); row->mmap_ok = 1;
      munmap(mapping, (size_t)row->bytes);
    }
    (*env)->DeleteLocalRef(env, digest);
    if (file) fclose(file); else close(fd);
  }
  (*env)->DeleteLocalRef(env, digest_buffer); (*env)->DeleteLocalRef(env, algorithm); (*env)->DeleteLocalRef(env, digest_class);
}
