/* Shared by the measured fixture bridge and the opt-in persistent module. */
#ifndef REPACK_FILE_IMPORTS_H
#define REPACK_FILE_IMPORTS_H
#include "bytehook.h"
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
enum { SYMBOLS = 14, TASKS = SYMBOLS * 2 };
static const char *const symbols[SYMBOLS] = {"open", "open64", "__open_2", "openat", "openat64", "__openat_2",
  "fopen", "fopen64", "stat", "stat64", "fstat", "fstat64", "readlink", "readlinkat"};
static unsigned hits[SYMBOLS];
static const char *source_name, *retained_name;
static const char *mapped_path(const char *path) {
  return retained_name && source_name && path && !strcmp(path, source_name) ? retained_name : path;
}
static const char *mapped_read(const char *path, int flags) {
  return (flags & O_ACCMODE) == O_RDONLY && !(flags & (O_CREAT | O_TRUNC | O_APPEND)) ? mapped_path(path) : path;
}
typedef struct { int library, symbol, status; bytehook_stub_t stub; } task_record;
static task_record tasks[TASKS];
#define HIT(N) __atomic_add_fetch(&hits[N], 1, __ATOMIC_RELAXED)
#define RETURN_VALUE(EXPR, TYPE) do { TYPE repack_return_value = (EXPR); int repack_saved_errno = errno; BYTEHOOK_POP_STACK(); errno = repack_saved_errno; return repack_return_value; } while (0)
typedef int (*open_fn)(const char *, int, ...);
typedef int (*openat_fn)(int, const char *, int, ...);
static int mode_needed(int flags) { return (flags & O_CREAT) || ((flags & O_TMPFILE) == O_TMPFILE); }
#define OPEN_PROXY(NAME, N) static int NAME(const char *path, int flags, ...) { \
  mode_t mode = 0; if (mode_needed(flags)) { va_list args; va_start(args, flags); mode = (mode_t)va_arg(args, int); va_end(args); } \
  HIT(N); RETURN_VALUE(BYTEHOOK_CALL_PREV(NAME, open_fn, mapped_read(path, flags), flags, mode), int); }
#define OPENAT_PROXY(NAME, N) static int NAME(int fd, const char *path, int flags, ...) { \
  mode_t mode = 0; if (mode_needed(flags)) { va_list args; va_start(args, flags); mode = (mode_t)va_arg(args, int); va_end(args); } \
  HIT(N); RETURN_VALUE(BYTEHOOK_CALL_PREV(NAME, openat_fn, fd, mapped_read(path, flags), flags, mode), int); }
OPEN_PROXY(h_open, 0)
OPEN_PROXY(h_open64, 1)
OPENAT_PROXY(h_openat, 3)
OPENAT_PROXY(h_openat64, 4)
static int h_open2(const char *path, int flags) {
  HIT(2); RETURN_VALUE(BYTEHOOK_CALL_PREV(h_open2, int (*)(const char *, int), mapped_read(path, flags), flags), int);
}
static int h_openat2(int fd, const char *path, int flags) {
  HIT(5); RETURN_VALUE(BYTEHOOK_CALL_PREV(h_openat2, int (*)(int, const char *, int), fd, mapped_read(path, flags), flags), int);
}
#define TWO_PROXY(NAME, N, RET, T1, T2) static RET NAME(T1 first, T2 second) { \
  HIT(N); RETURN_VALUE(BYTEHOOK_CALL_PREV(NAME, RET (*)(T1, T2), first, second), RET); }
#define FOPEN_PROXY(NAME, N) static FILE *NAME(const char *path, const char *mode) { \
  HIT(N); const char *selected = mode && mode[0] == 'r' && !strchr(mode, '+') ? mapped_path(path) : path; \
  RETURN_VALUE(BYTEHOOK_CALL_PREV(NAME, FILE *(*)(const char *, const char *), selected, mode), FILE *); }
FOPEN_PROXY(h_fopen, 6)
FOPEN_PROXY(h_fopen64, 7)
static int h_stat(const char *path, struct stat *value) {
  HIT(8); RETURN_VALUE(BYTEHOOK_CALL_PREV(h_stat, int (*)(const char *, struct stat *), mapped_path(path), value), int);
}
static int h_stat64(const char *path, struct stat64 *value) {
  HIT(9); RETURN_VALUE(BYTEHOOK_CALL_PREV(h_stat64, int (*)(const char *, struct stat64 *), mapped_path(path), value), int);
}
TWO_PROXY(h_fstat, 10, int, int, struct stat *)
TWO_PROXY(h_fstat64, 11, int, int, struct stat64 *)
static ssize_t h_readlink(const char *path, char *buffer, size_t size) {
  HIT(12); RETURN_VALUE(BYTEHOOK_CALL_PREV(h_readlink, ssize_t (*)(const char *, char *, size_t), path, buffer, size), ssize_t);
}
static ssize_t h_readlinkat(int fd, const char *path, char *buffer, size_t size) {
  HIT(13); RETURN_VALUE(BYTEHOOK_CALL_PREV(h_readlinkat, ssize_t (*)(int, const char *, char *, size_t), fd, path, buffer, size), ssize_t);
}
static void *const proxies[SYMBOLS] = {(void *)h_open, (void *)h_open64, (void *)h_open2, (void *)h_openat,
  (void *)h_openat64, (void *)h_openat2, (void *)h_fopen, (void *)h_fopen64, (void *)h_stat, (void *)h_stat64,
  (void *)h_fstat, (void *)h_fstat64, (void *)h_readlink, (void *)h_readlinkat};

static void hooked(bytehook_stub_t stub, int status, const char *caller, const char *symbol,
                   void *replacement, void *previous, void *arg) {
  (void)stub; (void)caller; (void)symbol; (void)replacement; (void)previous;
  task_record *task = arg;
  if (status != BYTEHOOK_STATUS_CODE_ORIG_ADDR) __atomic_store_n(&task->status, status, __ATOMIC_RELEASE);
}
static void hook_one(int library, int symbol) {
  task_record *task = &tasks[library * SYMBOLS + symbol];
  task->library = library; task->symbol = symbol; task->status = -99;
  task->stub = bytehook_hook_single(libraries[library], NULL, symbols[symbol], proxies[symbol], hooked, task);
}

#endif
