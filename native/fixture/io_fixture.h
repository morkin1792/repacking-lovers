#ifndef REPACK_IO_FIXTURE_H
#define REPACK_IO_FIXTURE_H
#include <stdint.h>
#include <jni.h>
#define IO_PATHS 11
typedef struct {
  int ok, error, link_ok, linkat_ok, link_retained, linkat_retained;
  int64_t bytes, path_size, path64_size, fd_size, fd64_size;
  uint64_t hash;
  unsigned char sha256[32];
  char link_target[512];
  int offsets_ok, mmap_ok, mmap_error, duplicate_retained;
  int64_t duplicate_size;
  unsigned char mmap_sha256[32];
} io_result;
typedef void (*io_probe_fn)(JNIEnv *, const char *, const char *, int, io_result *);
static const char *const io_names[IO_PATHS] = {
  "open", "open64", "__open_2", "openat", "openat64", "__openat_2", "fopen", "fopen64",
  "raw-syscall", "dlsym-open", "preopened-fd"
};
#endif
