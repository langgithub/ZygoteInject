#include "loader.h"

#define LOG_TAG "debug"
#include "log.h"

#ifdef __cplusplus
extern "C"
{
#endif

// check file system flag
static char *g_pszSelinuxFileSystemString=NULL;
static char **g_pSelinuxFileSystemStringPointer = &g_pszSelinuxFileSystemString;

// wrap the waitpid syscall and deal with the result.
int WaitPid(pid_t pid, int *status, int option) {
	while (waitpid(pid, status, option) == -1) {
		if (errno == EINTR) 
			continue;
		else
			return -1;
	}
	
	return 0;
}

// wrap PTRACE_ATTACH call, don't need WaitPid result maybe because we default think it's ok.
static int Attach(pid_t pid) {
	int res=0;
	int status=0;
	
	res = ptrace(PTRACE_ATTACH, pid, NULL, NULL);
	if (res < 0) {
		LOGE("<injectso.c:%d> attach failed:%s\n", __LINE__, strerror(errno));

		return -1;
	}

	WaitPid(pid, &status, 0);

	return res;
}

// wrap PTRACE_DETACH call, if don't success, we send a signal and do PTRACE_DETACH again.
static int Detach(pid_t pid) {
	int res=0, waitStatus=0;
	
	res = ptrace(PTRACE_DETACH, pid, NULL, NULL);
	if (res >= 0)
		return 0;

	kill(pid, SIGSTOP);

	LOGE("<injectso.c:%d> send stop signal\n", __LINE__);
	
	res = WaitPid(pid, &waitStatus, 0);
	if (res < 0) {
		LOGE("<injectso.c:%d> failed to send stop signal:%s\n", __LINE__, strerror(errno));
	}

	ptrace(PTRACE_DETACH, pid, NULL, NULL);

	return 0;
}

// wrap PTRACE_GETREGS call.
static int GetRegs(pid_t pid, struct pt_regs *data) {
	int res=0;
	
	res = ptrace(PTRACE_GETREGS, pid, NULL, data);
	if (res < 0) {
		LOGE("<injectso.c:%d> getregs failed:%s\n", __LINE__, strerror(errno));
		
		return -1;
	}

	return res;
}

// this function do a routing of syscall in the remote  with ptrace
static int invokeRemoteSyscall(pid_t pid, struct pt_regs *regs) {
	int ret=0, waitStatus=0;

	do {
		// you must prepare the syscall function address and fuction argments,sometimes need POKEDATA action.
		ret = ptrace(PTRACE_SETREGS, pid, NULL, regs);
		if (ret < 0) {
			LOGE("<injectso.c:%d> set regs failed:%s\n", __LINE__, strerror(errno));
			
			break;
		}

		ret = ptrace (PTRACE_SYSCALL, pid, NULL, NULL);
		if (ret < 0) {
			LOGE("<injectso.c:%d> syscall failed:%s\n", __LINE__, strerror(errno));
			
			break;
		}

		ret = WaitPid(pid, &waitStatus, 0);
		if (ret < 0) {
			LOGE("<injectso.c:%d> waitpid failed:%s\n", __LINE__, strerror(errno));
			
			break;
		}

		ret = ptrace (PTRACE_SYSCALL, pid, NULL, NULL);
		if (ret < 0) {
			LOGE("<injectso.c:%d> syscall failed:%s\n", __LINE__, strerror(errno));
			
			break;
		}

		ret = WaitPid(pid, &waitStatus, 0);
		if (ret < 0) {
			LOGE("<injectso.c:%d> waitpid failed:%s\n", __LINE__, strerror(errno));
			
			break;
		}
	}while (0);

	return ret;
}

// this function do a routing of executing shellcodeDataBuffer in the remote process with ptrace
static int invokeRemoteShellcode(pid_t pid, struct pt_regs *regs) {
	int ret=0, waitStatus=0;

	do {
		// this put our regs setting to the remote process memory space,
			//the code must have been stored with POKEDATA at first
		ret = ptrace(PTRACE_SETREGS, pid, NULL, regs);
		if (ret < 0) {
			LOGE("<injectso.c:%d> set regs failed:%s\n", __LINE__, strerror(errno));

			break;
		}

		// let shellcodeDataBuffer enter executing routing
		ret = ptrace(PTRACE_CONT, pid, NULL, NULL);
		if (ret < 0) {
			LOGE("<injectso.c:%d> CONT failed:%s\n", __LINE__, strerror(errno));
			
			break;
		}

		// wait for the shellcodeDataBuffer to finish executing,this must be triggled by shellcodeDataBuffer
		ret = WaitPid(pid, &waitStatus, 0);
		if (ret < 0) {
			LOGE("<injectso.c:%d> waitpid failed:%s\n", __LINE__, strerror(errno));
			
			break;
		}
	} while (0);

	return ret;
}

static int injectProcess(pid_t pid, char *libraryPath, char *entryFunctionName, char *functionArg) {
	int ret=0, waitStatus=0, shellcodeDataIndex=0;
	char shellcodeDataBuffer[0x400]={0};
	struct pt_regs orignalRegisters={0}, usingRegisters={0};
	void *libcHandler=NULL, *linkerHandler=NULL;
	void *mmap_self_addr=NULL, *munmap_self_addr=NULL, *mprotect_self_addr=NULL, 
		*dlopen_self_addr=NULL, *dlsym_self_addr=NULL, *dlclose_self_addr=NULL, *dlerror_self_addr=NULL;
	void *mmap_remote_addr=NULL, *munmap_remote_addr=NULL, *mprotect_remote_addr=NULL,
		*dlopen_remote_addr=NULL, *dlsym_remote_addr=NULL, *dlclose_remote_addr=NULL, *dlerror_remote_addr=NULL;
	void *mmap_return=NULL;

	extern uint32_t _inject_code_start, _inject_code_end,  _dlopen_param2, _saved_cpsr_value, _dlopen_addr, _dlsym_addr, 
		_dlclose_addr, _dlerror_addr, _so_path_addr, _so_init_func_addr, _so_func_arg_addr, _saved_r0_pc_addr,
		_so_path_value, _so_init_func_value, _so_func_arg_value, _saved_r0_pc_value;

	if (libraryPath == NULL || entryFunctionName == NULL || functionArg == NULL)
		return -1;
	
	if (getModuleBase(pid, libraryPath) != (void *)-1) {
		LOGE("you have already inject this library, detach\n");

		return 0;
	}
	
	if (Attach(pid) < 0)
		return -1;

	// get the original regs when we just attach,restore at the end.
	ret = GetRegs(pid, &orignalRegisters);
	if (!ret) {
		do {
			LOGE("attch pass\n");

			// copy one for debuging process
			memcpy(&usingRegisters, &orignalRegisters, sizeof(orignalRegisters));

			// get remote mmap,munmap,mprotect func addr
			libcHandler = dlopen(LIBC_PATH, RTLD_NOW);
			mmap_self_addr = dlsym(libcHandler, MMAP_NAME);
			munmap_self_addr = dlsym(libcHandler, MUNMAP_NAME);
			mprotect_self_addr = dlsym(libcHandler, MPROTECT_NAME);
			mmap_remote_addr = getRemoteSymbolAddress(pid, LIBC_PATH, mmap_self_addr);
			munmap_remote_addr = getRemoteSymbolAddress(pid, LIBC_PATH, munmap_self_addr);
			mprotect_remote_addr = getRemoteSymbolAddress(pid, LIBC_PATH, mprotect_self_addr);

			// prepare call mmap in the remote process
			usingRegisters.uregs[0] = 0;
			usingRegisters.uregs[1] = 0x4000;
			usingRegisters.uregs[2] = PROT_EXEC | PROT_READ | PROT_WRITE;
			usingRegisters.uregs[3] = MAP_ANONYMOUS | MAP_PRIVATE;
			usingRegisters.uregs[13] -= sizeof(long);
			ptrace(PTRACE_POKEDATA, pid, (void *)(usingRegisters.uregs[13]), 0);
			usingRegisters.uregs[13] -= sizeof(long);
			ptrace(PTRACE_POKEDATA, pid, (void *)(usingRegisters.uregs[13]), (void *)0xffffffff);

			usingRegisters.uregs[15] = (long)mmap_remote_addr;
			if (usingRegisters.uregs[15] & 1u) {
				usingRegisters.uregs[15] &= (~1u);
				usingRegisters.uregs[16] |= CPSR_T_MASK;
			} else {
				usingRegisters.uregs[16] &= ~CPSR_T_MASK;
			}

			// call mmap in the remote process
			ret = invokeRemoteSyscall(pid, &usingRegisters);
			if (ret < 0) break;

			// check mmap result.
			ret = GetRegs(pid, &usingRegisters);
			if (ret < 0)  break;

			LOGE("call remote mmap res:%p\n", (void *)(usingRegisters.uregs[0]));

			// save the mmap return value, we will put shellcodeDataBuffer there.
			mmap_return = (void *)(usingRegisters.uregs[0]);

			linkerHandler = dlopen(LIBDL_NAME, RTLD_NOW);
			dlopen_self_addr = dlsym(linkerHandler, "dlopen");
			dlsym_self_addr = dlsym(linkerHandler, "dlsym");
			dlclose_self_addr = dlsym(linkerHandler, "dlclose");
			dlerror_self_addr = dlsym(linkerHandler, "dlerror");
			dlopen_remote_addr = getRemoteSymbolAddress(pid, LINKER_PATH, dlopen_self_addr);
			dlsym_remote_addr = getRemoteSymbolAddress(pid, LINKER_PATH, dlsym_self_addr);
			dlclose_remote_addr = getRemoteSymbolAddress(pid, LINKER_PATH, dlclose_self_addr);
			dlerror_remote_addr = getRemoteSymbolAddress(pid, LINKER_PATH, dlerror_self_addr);

			if (dlopen_remote_addr == NULL || dlsym_remote_addr == NULL || dlclose_remote_addr == NULL 
				|| dlerror_remote_addr == NULL) {
				LOGE("can't get dl imports\n");

				break;
			}

			memcpy(&usingRegisters, &orignalRegisters, sizeof(orignalRegisters));
			memset(shellcodeDataBuffer, 0, 0x400);
			memcpy(shellcodeDataBuffer, &_inject_code_start, (&_inject_code_end - &_inject_code_start) * sizeof(uint32_t));
			*(uint32_t*) (shellcodeDataBuffer+(&_dlopen_addr - &_inject_code_start)*sizeof(uint32_t)) = (uint32_t)dlopen_remote_addr;
			*(uint32_t*) (shellcodeDataBuffer+(&_dlsym_addr - &_inject_code_start)*sizeof(uint32_t)) = (uint32_t)dlsym_remote_addr;
			*(uint32_t*) (shellcodeDataBuffer+(&_dlclose_addr - &_inject_code_start)*sizeof(uint32_t)) = (uint32_t)dlclose_remote_addr;
			*(uint32_t*) (shellcodeDataBuffer+(&_dlerror_addr - &_inject_code_start)*sizeof(uint32_t)) = (uint32_t)dlerror_remote_addr;

			strncpy(shellcodeDataBuffer+(&_so_path_value - &_inject_code_start)*sizeof(uint32_t), libraryPath, 255);
			strncpy(shellcodeDataBuffer+(&_so_init_func_value - &_inject_code_start)*sizeof(uint32_t), entryFunctionName, 255);
			if (functionArg != NULL) {
				memcpy(shellcodeDataBuffer+(&_so_func_arg_value - &_inject_code_start)*sizeof(uint32_t), functionArg, 255);
			}

			*(uint32_t*)(shellcodeDataBuffer+(&_saved_cpsr_value - &_inject_code_start)*sizeof(uint32_t)) = orignalRegisters.uregs[16];
			memcpy(shellcodeDataBuffer+(&_saved_r0_pc_value - &_inject_code_start)*sizeof(uint32_t), &(orignalRegisters.uregs[0]), 16 * sizeof(long));

			usingRegisters.uregs[13] = (uint32_t)(mmap_return + 0x3c00);
			
			*(uint32_t*)(shellcodeDataBuffer+(&_so_path_addr - &_inject_code_start)*sizeof(uint32_t))
				= (uint32_t)((char *)usingRegisters.uregs[13] + (&_so_path_value - &_inject_code_start) * sizeof(uint32_t));
			*(uint32_t*)(shellcodeDataBuffer+(&_so_init_func_addr - &_inject_code_start)*sizeof(uint32_t))
				= (uint32_t)((char *)usingRegisters.uregs[13] + (&_so_init_func_value - &_inject_code_start) * sizeof(uint32_t));
			*(uint32_t*)(shellcodeDataBuffer+(&_so_func_arg_addr - &_inject_code_start)*sizeof(uint32_t))
				= (uint32_t)((char *)usingRegisters.uregs[13] + (&_so_func_arg_value - &_inject_code_start) * sizeof(uint32_t));
			*(uint32_t*)(shellcodeDataBuffer+(&_saved_r0_pc_addr - &_inject_code_start)*sizeof(uint32_t))
				= (uint32_t)((char *)usingRegisters.uregs[13] + (&_saved_r0_pc_value - &_inject_code_start) * sizeof(uint32_t));

			// store prepared shellcodeDataBuffer to remote process with PTRACE_POKEDATA
			shellcodeDataIndex = 0;
			while (shellcodeDataIndex < 0x400 / sizeof(uint32_t)) {
				ptrace(PTRACE_POKEDATA, pid, (void *)(usingRegisters.uregs[13]+shellcodeDataIndex * sizeof(uint32_t))
					, (void *)*(uint32_t *)((uint32_t *)shellcodeDataBuffer+shellcodeDataIndex));
				shellcodeDataIndex++;
			}

			usingRegisters.uregs[15] = usingRegisters.uregs[13];
			usingRegisters.uregs[16] &= ~CPSR_T_MASK;

			// call shellcodeDataBuffer in remote process
			ret = invokeRemoteShellcode(pid, &usingRegisters);
			if (ret < 0) break;

			// check shellcodeDataBuffer executing result.
			ret = GetRegs(pid, &usingRegisters);
			if (ret < 0) break;

			LOGE("call remote shellcode res:%d\n", (int)(usingRegisters.uregs[1]));

			if ((int)(usingRegisters.uregs[1]) == 1) {
				// dlopen failed in shellcodeDataBuffer
				int msg_index = 0;
				uint32_t *err_msg = (uint32_t *) calloc(0x101, 1);
				*(char *)err_msg = 0;

				while (msg_index < 0x40) {
					err_msg[msg_index] = ptrace(PTRACE_PEEKDATA, pid, (void *)(usingRegisters.uregs[2] + msg_index * sizeof(uint32_t)), 0);
					msg_index++;
				}
				
				LOGE("dlerror failed:%s\n", (char *)err_msg);

				free(err_msg);
			} 

			// prepare call munmap in the remote process
			memcpy(&usingRegisters, &orignalRegisters, sizeof(orignalRegisters));
			
			usingRegisters.uregs[0] = (long)mmap_return;
			usingRegisters.uregs[1] = 0x4000;

			usingRegisters.uregs[15] = (long)munmap_remote_addr;
			if (usingRegisters.uregs[15] & 1u) {
				usingRegisters.uregs[15] &= (~1u);
				usingRegisters.uregs[16] |= CPSR_T_MASK;
			} else {
				usingRegisters.uregs[16] &= ~CPSR_T_MASK;
			}

			// call munmap in the remote process, don't need check result
				//because we will restore remote process to the original status right after now.
			ret = invokeRemoteSyscall(pid, &usingRegisters);
			if (ret < 0) break;

			ret = GetRegs(pid, &usingRegisters);
			if (ret < 0) break;

			// check original status
			do {
				LOGE("%s:%d r0:%ld, orig_r0:%ld, r7:%ld, pc:%ld, cpsr:%ld\n", __FUNCTION__, __LINE__
					, orignalRegisters.ARM_r0, orignalRegisters.ARM_ORIG_r0, orignalRegisters.ARM_r7, orignalRegisters.ARM_pc, orignalRegisters.ARM_cpsr);
				if (orignalRegisters.ARM_r0 == -0x204) {
					LOGE("%s:%d r0 == -0x204\n", __FUNCTION__, __LINE__);
					orignalRegisters.ARM_r0 = -11;
					if (orignalRegisters.ARM_cpsr & 0x20) {
						LOGE("%s:%d thumb\n", __FUNCTION__, __LINE__);
						orignalRegisters.ARM_pc -= 2;
						orignalRegisters.ARM_r7 = 0;
					} else {
						LOGE("%s:%d arm\n", __FUNCTION__, __LINE__);
						orignalRegisters.ARM_pc -= 4;
						orignalRegisters.ARM_r7 = 0;
					}

					break;
				}

				if (orignalRegisters.ARM_r0 != -0x200 && orignalRegisters.ARM_r0 != -514) {
					LOGE("%s:%d r0 not -0x200 and -514\n", __FUNCTION__, __LINE__);
					if (orignalRegisters.ARM_r0 != -513) {
						LOGE("%s:%d r0 not -513\n", __FUNCTION__, __LINE__);
						break;
					}

					LOGE("%s;%d r0 == -513\n", __FUNCTION__, __LINE__);
				}

				if (orignalRegisters.ARM_ORIG_r0 != -0x200) {
					LOGE("%s:%d orig_r0 != -512\n", __FUNCTION__, __LINE__);
					if (orignalRegisters.ARM_ORIG_r0 == -514) {
						LOGE("%s:%d orig_r0 == -514\n", __FUNCTION__, __LINE__);
						orignalRegisters.ARM_r0 = -4;
						break;
					}

					LOGE("%s:%d orig_r0 not -514\n", __FUNCTION__, __LINE__);
				}

				if (orignalRegisters.ARM_ORIG_r0 == -513) {
					LOGE("%s:%d orig_r0 == -513\n", __FUNCTION__, __LINE__);
					orignalRegisters.ARM_r0 = -4;
					break;
				}

				if (orignalRegisters.ARM_ORIG_r0 == -0x204) {
					LOGE("%s;%d orig_r0 == -0x204\n", __FUNCTION__, __LINE__);
					orignalRegisters.ARM_r0 = -4;
					break;
				}

				orignalRegisters.ARM_r0 = orignalRegisters.ARM_ORIG_r0;
				if (orignalRegisters.ARM_cpsr & 0x20) {
					LOGE("%s:%d thumb\n", __FUNCTION__, __LINE__);
					orignalRegisters.ARM_pc -= 2;
				} else {
					LOGE("%s:%d arm\n", __FUNCTION__, __LINE__);
					orignalRegisters.ARM_pc -= 4;
				}
			} while (0);
		} while (0);

		// put remote process back to the orignal status when it is just attached.
		if (ptrace(PTRACE_SETREGS, pid, NULL, &orignalRegisters) < 0) {
			LOGE("restore original registers failed:%s\n", strerror(errno));
		}
	}

	return Detach(pid);
}

// check if we have the perm to attach process and arg list format,if both ok,record in the log.
static int isUserValid() {
	// check if our process has perm to ptrace
	if ((getuid() != 0) || (geteuid() != 0)) {
		LOGE("you are not prevelege user\n");
		
		return -1;
	}
	
	return 0;
}

static int isArgListValid(int argc, char **argv) {
	// check if arg list len is right.
	if (argc != 5)
	{
		LOGE("arg list len is invalid\n");

		return -1;
	}

	LOGE("\n\n\n\n\ninjecting! (%s %s %s %s)\n", argv[1], argv[2], argv[3], argv[4]);

	return 0;
}

static void checkSelinuxSystem() {
	if (*g_pSelinuxFileSystemStringPointer == NULL) {
		int ret=0;
		FILE *pFilesystems=NULL;
		char fileLineBuffer[1024]={0};
		struct statfs statfsBuffer={0};

		while ((ret = statfs("/sys/fs/selinux", &statfsBuffer)) < 0) {
			if (errno == EINTR)
				continue;
			
			LOGE("statfs error:%s\n", strerror(errno));
			
			return ;
		}

		if (ret == 0 && statfsBuffer.f_type == 0xF97CFF8C ) {
			*g_pSelinuxFileSystemStringPointer = strdup("/sys/fs/selinux");

			return;
		}

		pFilesystems = fopen("/proc/filesystems", "r");
		if (pFilesystems == NULL)
			return ;

		do {
			if (fgets(fileLineBuffer, 1024, pFilesystems) == NULL) {
				fclose(pFilesystems);
				return ;
			}

			if (strstr(fileLineBuffer, "selinuxfs")) {
				break;
			}
		} while (1);

		fclose(pFilesystems);

		pFilesystems = fopen("/proc/mounts", "r");
		if (pFilesystems == NULL)
			return ;

		do {
			char *spacePosition;
			char *fileSystemName;
			
			if (fgets(fileLineBuffer, 1024, pFilesystems) == NULL) {
				fclose(pFilesystems);
				return ;
			}

			spacePosition = strchr(fileLineBuffer, ' ');
			if (spacePosition == NULL) {
				fclose(pFilesystems);
				return ;
			}

			spacePosition++;
			fileSystemName = spacePosition;
			spacePosition = strchr(fileSystemName, ' ');
			if (spacePosition == NULL) {
				fclose(pFilesystems);
				return ;
			}

			spacePosition++;

			if (strncmp(spacePosition, "selinuxfs ", 10) != 0)
				continue;

			*(spacePosition -1) = 0;
			*g_pSelinuxFileSystemStringPointer = strdup(fileSystemName);
			break;
		} while (1);

		fclose(pFilesystems);
	}
}

static int getSelinuxFlag() {
	int fd=0, readLength=0, value=0;
	char fileContentBuffer[20]={0};
	char filePath[1024]={0};
	
	if (*g_pSelinuxFileSystemStringPointer == NULL) {
		errno = 2;
		return -1;
	}

	snprintf(filePath, 1024, "%s/enforce", *g_pSelinuxFileSystemStringPointer);
	fd = open(filePath, 0);
	if (fd < 0)
		return -1;

	memset(fileContentBuffer, 0, 20);
	readLength = read(fd, fileContentBuffer, 19);
	close(fd);

	if (readLength < 0)
		return -1;

	readLength = sscanf(fileContentBuffer, "%d", &value);
	if (readLength != 1)
		return -1;

	return value;
}

static int setSelinuxFlag(int value) {
	int fd=0, len=0;
	char fileContentBuffer[20]={0};
	char filePath[1024]={0};
	
	if (*g_pSelinuxFileSystemStringPointer == NULL) {
		errno = 2;
		return -1;
	}

	snprintf(filePath, 1024, "%s/enforce", *g_pSelinuxFileSystemStringPointer);
	fd = open(filePath, 2);
	if (fd < 0)
		return -1;

	snprintf(fileContentBuffer, 20, "%d", value);
	len = strlen(fileContentBuffer);
	
	len = write(fd, fileContentBuffer, len);

	close(fd);

	return len >> 31;
}

int main(int argc, char **argv)
{
	pid_t targetPid=0;
	int ret=0, nSelinuxFlag=0, i=0;
	char *pszLibraryName=NULL;
	char injectArg[256]={0};
	FILE *fp=NULL;
	
	if (isUserValid() != 0)
	{
		return -1;
	}

	if (argc < 4)
	{
		LOGE("arg list min len is invalid\n");

		return -1;
	}

#if 0

	if (strcmp(argv[4], "1") == 0)
	{
		if (argc != 9)
		{
			LOGE("arg list max len is invalid\n");

			return -1;
		}
	}
	else if (strcmp(argv[4], "0") == 0)
	{
		if (argc != 6)
		{
			LOGE("arg list min len is invalid\n");

			return -1;
		}
	}
	else
	{
		if (isArgListValid(argc, argv) != 0)
		{
			return -1;
		}
	}
#endif

	targetPid = atoi(argv[1]);
	if (targetPid <= 0)
	{
		LOGE("target pid invalid\n");

		return -1;
	}

	// check if arg2 is a full path to so
	pszLibraryName = strrchr(argv[2], '/');
	if (pszLibraryName == NULL)
	{
		LOGE("library path not an absolute path\n");

		return -1;
	}

	// check if process has already been injected by us before.
	pszLibraryName++;
	if (getModuleBase(targetPid, basename(argv[2])) != (void *)-1)
	{
		LOGE("you have inject this library to maps\n");

		return -1;
	}

	// check system version such as selinux here
	//checkSelinuxSystem();
	//nSelinuxFlag = getSelinuxFlag();
	//setSelinuxFlag(0);

	memset(injectArg, 0, 256);

	for (i = 4; i < argc; i++)
	{
		strcat(injectArg, argv[i]);
		if (i == argc -1)
			break;
		strcat (injectArg, " ");
	}

	LOGE("inject arg:%s\n", injectArg);

	ret = injectProcess(targetPid, argv[2], argv[3], injectArg);

	snprintf(injectArg, 255, INJECT_MAPS_PATH, targetPid);
	fp = fopen(injectArg, "w+");
	if (fp == NULL)
		return -1;
	dumpProcessMaps(targetPid, fp);
	fclose(fp);

	//setSelinuxFlag(nSelinuxFlag);

	LOGE("inject finish\n");

	return ret;
}

#ifdef __cplusplus
}
#endif

