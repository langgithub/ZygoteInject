#ifndef CTOOLS_H_
#define CTOOLS_H_

#include <errno.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include <libgen.h>
#include <fcntl.h>
#include <dlfcn.h>

#include <sys/cdefs.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifdef __cplusplus
extern "C"
{
#endif

int readSockWithLen(int nSockFd, void *pbReadBuffer, int nNeedLen);

int writeSockWithLen(int nSockFd, void *pbWriteBuffer, int nNeedLen);

int send_msg_with_len(int nSendFd, void *plSendBuffer, int nSendLen);

void logBufferInHexWithLen(char *pbBuffer, int nBufferLen);

void logIntHexWithFour(unsigned *pbBuffer, int nBufferLen);

void logIntHexWithLen(unsigned *pbBuffer, int nBufferLen);

unsigned getUnsignedFromBuffer(char *pbBuffer);

void *getModuleBase(pid_t pid, char *module_name);
void *getRemoteSymbolAddress(pid_t pid, char *module_name, void *func_addr);

int dumpProcessMaps(pid_t pid, FILE *outFilePtr);

int logProcessMaps(pid_t pid);

int get_proc_name(pid_t pid, char *name, int len);

char * get_module_full_name(pid_t pid, const char *name);

int rmCodeProtection(unsigned *uMemAddr, int nMemSize, unsigned uProt);

void get_strftime(char *time_buffer, int size);

char *trimwhitespace(char *str);

unsigned get_module_base_from_func_addr(unsigned func_addr);

int is_addr_valid(unsigned addr);

int is_addr_valid2(unsigned addr);

int branch_offset_extension(int offset);

#ifdef __cplusplus
}
#endif

#endif
