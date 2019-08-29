#ifndef XXINJECTSO_H_
#define XXINJECTSO_H_

#include <unistd.h>
#include <stdio.h>
#include <dlfcn.h>
#include <signal.h>
#include <linux/ptrace.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/vfs.h>
#include <sys/syscall.h>

#define LIBC_PATH "/system/lib/libc.so"
#define LINKER_PATH "/system/bin/linker"
#define LIBDL_NAME "libdl.so"

#define MMAP_NAME "mmap"
#define MUNMAP_NAME "munmap"
#define MPROTECT_NAME "mprotect"

#define CPSR_T_MASK (1u<<5)

#define INJECT_MAPS_PATH "/sdcard/%d.maps"

#endif
