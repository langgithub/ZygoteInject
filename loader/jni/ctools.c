#include "ctools.h"
#define LOG_TAG "<MD-ctools>"
#include "log.h"

#ifdef __cplusplus
extern "C"
{
#endif

/*
 *	Description: ��socket��ָ�����ȵ���ݣ��������
 *	Input:
 *		nSockFd socket�׽���
 *		pbReadBuffer ��Ŷ����ݵ��ڴ���ַ
 *		nNeedLen Ҫ��ȡ�����ݳ���
 *	Output: pbReadBuffer ��Ŷ���������
 *	Return: -1��ʾ��ȡʧ�ܣ� �����ʾ���������ݳ���
 *	Others: ��
 */
int readSockWithLen(int nSockFd, void *pbReadBuffer, int nNeedLen) {
	int nRead = 0, nReadTotal = 0;

	while (nReadTotal < nNeedLen) {
		nRead = read(nSockFd, pbReadBuffer+nReadTotal, nNeedLen - nReadTotal);
		if (nRead < 0) {
			LOGE("read error:%s\n", strerror(errno));
			return -1;
		} else if (nRead == 0) {
			LOGE(" read socket close\n");
			break;
		} else {
			nReadTotal += nRead;
		}
	}

	return nReadTotal;
}

/*
 *	Description: ��socketдָ�����ȵ���ݣ��������
 *	Input:
 *		nSockFd socket�׽���
 *		pbWriteBuffer ��Ŷ����ݵ��ڴ���ַ
 *		nNeedLen Ҫ��ȡ�����ݳ���
 *	Output:
 *	Return: -1��ʾ��ȡʧ�ܣ� �����ʾд�ɵ����ݳ���
 *	Others: ��
 */
int writeSockWithLen(int nSockFd, void *pbWriteBuffer, int nNeedLen)
{
	int nWrite = 0, nWriteTotal = 0;

	while (nWriteTotal < nNeedLen)
	{
		nWrite = write(nSockFd, pbWriteBuffer+nWriteTotal, nNeedLen - nWriteTotal);
		if (nWrite < 0)
		{
			LOGE(" write error:%s\n", strerror(errno));
			return -1;
		}
		else if (nWrite == 0)
		{
			LOGE(" write server close\n");
			break;
		}
		else
		{
			nWriteTotal += nWrite;
		}
	}

	return nWriteTotal;
}

int send_msg_with_len(int nSendFd, void *plSendBuffer, int nSendLen)
{
	char pbLenBuffer[4];

	pbLenBuffer[0] = pbLenBuffer[1] = 0;
	pbLenBuffer[2] = ((nSendLen >> 8) & 0xff);
	pbLenBuffer[3] = (nSendLen &0xff);

	logBufferInHexWithLen(pbLenBuffer, 4);

	// �ȷ������ݳ���
	if (writeSockWithLen(nSendFd, pbLenBuffer, 4) != 4)
	{
		LOGE("[SEND] send len failed:%s\n", strerror(errno));
		return -1;
	}

	// ����ʵ������
	if (writeSockWithLen(nSendFd, plSendBuffer, nSendLen) != nSendLen)
	{
		LOGE("[SEND] send lDefaultReply failed:%s\n", strerror(errno));
		return -1;
	}

	return 0;
}

/*
 *	Description: ��16���ƴ�ӡ�ڴ�飬��������ڴ����ݡ�
 *	Input:
 *		pbBuffer �ڴ��ָ��
 *		nBufferLen Ҫ��ӡ���ڴ�鳤��
 *	Output: ��
 *	Return: ��
 *	Others: ��
 */
void logBufferInHexWithLen(char *pbBuffer, int nBufferLen)
{
	if (nBufferLen <= 0 || pbBuffer == NULL)
	{
		return;
	}

	while(nBufferLen >= 8)
	{
		LOGE("%.2X %.2X %.2X %.2X %.2X %.2X %.2X %.2X"
				, *(char *)pbBuffer, *((char *)pbBuffer + 1), *((char *)pbBuffer + 2), *((char *)pbBuffer + 3)
				, *((char *)pbBuffer + 4), *((char *)pbBuffer + 5), *((char *)pbBuffer + 6), *((char *)pbBuffer + 7));

		pbBuffer += 8;
		nBufferLen -= 8;
	}

	while (nBufferLen >= 4)
	{
		LOGE("%.2X %.2X %.2X %.2X", *(char *)pbBuffer, *((char *)pbBuffer + 1)
				, *((char *)pbBuffer + 2), *((char *)pbBuffer + 3));
		pbBuffer += 4;
		nBufferLen -= 4;
	}

	while (nBufferLen >= 2)
	{
		LOGE("%.2X %.2X", *(char *)pbBuffer, *((char *)pbBuffer + 1));
		pbBuffer += 2;
		nBufferLen -= 2;
	}

	while (nBufferLen >= 1)
	{
		LOGE("%.2X", *(char *)pbBuffer);
		pbBuffer += 1;
		nBufferLen -= 1;
	}
}

void logIntHexWithLen(unsigned *pbBuffer, int nBufferLen)
{
	if (nBufferLen <= 0 || pbBuffer == NULL)
	{
		return;
	}

	while(nBufferLen >= 8)
	{
		LOGE("%.8X %.8X %.8X %.8X %.8X %.8X %.8X %.8X"
				, *pbBuffer, *(pbBuffer + 1), *(pbBuffer + 2), *(pbBuffer + 3)
				, *(pbBuffer + 4), *(pbBuffer + 5), *(pbBuffer + 6), *(pbBuffer + 7));

		pbBuffer += 8;
		nBufferLen -= 8;
	}

	while (nBufferLen >= 4)
	{
		LOGE("%.8X %.8X %.8X %.8X", *pbBuffer, *(pbBuffer + 1)
				, *(pbBuffer + 2), *(pbBuffer + 3));
		pbBuffer += 4;
		nBufferLen -= 4;
	}

	while (nBufferLen >= 2)
	{
		LOGE("%.8X %.8X", *pbBuffer, *(pbBuffer + 1));
		pbBuffer += 2;
		nBufferLen -= 2;
	}

	while (nBufferLen >= 1)
	{
		LOGE("%.8X", *pbBuffer);
		pbBuffer += 1;
		nBufferLen -= 1;
	}
}

void logIntHexWithFour(unsigned *pbBuffer, int nBufferLen)
{
	if (nBufferLen <= 0 || pbBuffer == NULL)
	{
		return;
	}

	while (nBufferLen >= 4)
	{
		LOGE("%.8X %.8X %.8X %.8X", *pbBuffer, *(pbBuffer + 1)
				, *(pbBuffer + 2), *(pbBuffer + 3));
		pbBuffer += 4;
		nBufferLen -= 4;
	}

	if (nBufferLen > 0)
	{
		if (nBufferLen == 3)
		{
			LOGE("%.8X %.8X %.8X", *pbBuffer, *(pbBuffer + 1), *(pbBuffer + 2));
		}
		else if (nBufferLen == 2)
		{
			LOGE("%.8X %.8X", *pbBuffer, *(pbBuffer + 1));
		}
		else if (nBufferLen == 1)
		{
			LOGE("%.8X", *pbBuffer);
		}
	}
}

/*
 *	Description: ���ڴ���ж�ȡһ������������ֵ��ת����С�����ڴ����뱣֤����ȷ����ʼλ�ã����ҳ���Ϊ4����
 *	Input:
 *		pbBuffer �ڴ��ָ��
 *	Output: ��
 *	Return: ��ȷ������ֵ
 *	Others: ��
 */
unsigned getUnsignedFromBuffer(char *pbBuffer)
{
	if (pbBuffer == NULL)
		return 0;

	return ((pbBuffer[0] & 0xff) << 24)
				| ((pbBuffer[1] & 0xff) << 16)
				| ((pbBuffer[2] & 0xff) << 8)
				| (pbBuffer[3] & 0xff);
}

void init_len_buffer(char *pbBuffer, int len)
{
	pbBuffer[0] = pbBuffer[1] = 0;
	pbBuffer[2] = (len >> 8) & 0xff;
	pbBuffer[3] = len & 0xff;
}

void *getModuleBase(pid_t pid, char *moduleName) {
	FILE *fp;
	unsigned long baseValue;
	char mapFilePath[256];
	char fileLineBuffer[1024];

	if (pid < 0)
	{
		sprintf(mapFilePath, "/proc/self/maps");
	}
	else
	{
		sprintf(mapFilePath, "/proc/%d/maps", pid);
	}

	fp = fopen(mapFilePath, "r");
	if (fp == NULL)
		return (void *)-1;

	baseValue = -1;
	while (fgets(fileLineBuffer, sizeof(fileLineBuffer), fp) != NULL)
	{
		if (strstr(fileLineBuffer, moduleName))
		{
			char *pszModuleAddress = strtok(fileLineBuffer, "-");
			if (pszModuleAddress)
			{
				baseValue = strtoul(pszModuleAddress, NULL, 16);

				if (baseValue == 0x8000)
					baseValue = 0;

				break;
			}
		}
	}

	fclose(fp);

	return (void *)baseValue;
}

void *getRemoteSymbolAddress(pid_t pid, char *moduleName, void *selfSymbolAddress)
{
	void *selfModuleBase = getModuleBase(-1, moduleName);
	void *remoteModuleBase = getModuleBase(pid,  moduleName);

	if (remoteModuleBase == (void *) -1)
		return 0;

	return (selfSymbolAddress - selfModuleBase + remoteModuleBase);
}

int logProcessMaps(pid_t pid)
{
	FILE *fp;
	unsigned long baseValue;
	char mapFilePath[256];
	char fileLineBuffer[1024];

	if (pid < 0)
	{
		sprintf(mapFilePath, "/proc/self/maps");
	}
	else
	{
		sprintf(mapFilePath, "/proc/%d/maps", pid);
	}

	fp = fopen(mapFilePath, "r");
	if (fp == NULL)
		return (void *)-1;

	while (fgets(fileLineBuffer, sizeof(fileLineBuffer), fp) != NULL)
	{
		LOGE("%s", fileLineBuffer);
	}

	fclose(fp);

	return 0;
}

int dumpProcessMaps(pid_t pid, FILE *outFilePtr)
{
	FILE *fp;
	unsigned long baseValue;
	char mapFilePath[256];
	char fileLineBuffer[1024];
	char time_buffer[256];

	if (pid < 0)
	{
		sprintf(mapFilePath, "/proc/self/maps");
	}
	else
	{
		sprintf(mapFilePath, "/proc/%d/maps", pid);
	}

	fp = fopen(mapFilePath, "r");
	if (fp == NULL)
		return (void *)-1;

	get_strftime(time_buffer, 256);
	fprintf(outFilePtr, "dump at %s pid:%d", time_buffer, pid);

	while (fgets(fileLineBuffer, sizeof(fileLineBuffer), fp) != NULL)
	{
		fprintf(outFilePtr, "%s", fileLineBuffer);
	}

	fclose(fp);

	return 0;
}

int get_proc_name(pid_t pid, char *name, int len)
{
	char sym_name[256];
	FILE *fp;
	char cmdline[256];

	if (pid <= 0)
	{
		LOGD(" invalid pid:%d\n", pid);
		return -1;
	}

	sprintf(sym_name, "/proc/%d/cmdline", pid);

	fp = fopen(sym_name, "r");
	if (fp)
	{
		fgets(cmdline, sizeof(cmdline), fp);
		fclose(fp);
	}
	else
	{
		LOGD("no this file\n");
		fclose(fp);
		return -1;
	}

	strncpy(name, cmdline, len);
	return 0;
}

char * get_module_full_name(pid_t pid, const char *name)
{
	FILE *fp;
	char mapFilePath[256];
	char fileLineBuffer[1024];
	char *pItem;
	char *pItemBackup;

	if (pid < 0)
	{
		sprintf(mapFilePath, "/proc/self/maps");
	}
	else
	{
		sprintf(mapFilePath, "/proc/%d/maps", pid);
	}

	fp = fopen(mapFilePath, "r");
	if (fp == NULL)
	{
		LOGE("can't open maps, err:%s\n", strerror(errno));
		return NULL;
	}

	while (fgets(fileLineBuffer, sizeof(fileLineBuffer), fp) != NULL)
	{
		//LOGE("%s\n", fileLineBuffer);

		if (strstr(fileLineBuffer, name))
		{
			pItem = strtok_r(fileLineBuffer, " \t", &pItemBackup);
			pItem = strtok_r(NULL, " \t", &pItemBackup);
			pItem = strtok_r(NULL, " \t", &pItemBackup);
			pItem = strtok_r(NULL, " \t", &pItemBackup);
			pItem = strtok_r(NULL, " \t", &pItemBackup);
			pItem = strtok_r(NULL, " \t", &pItemBackup);

			if (pItem != NULL)
			{
				if (pItem[strlen(pItem) - 1] == '\n')
					pItem[strlen(pItem) - 1] = 0;

				fclose(fp);
				return strdup(pItem);
			}

			break;
		}
	}

	fclose(fp);

	return NULL;
}

int rmCodeProtection(unsigned *uMemAddr, int nMemSize, unsigned uProt)
{
	int nMemPageNum;
	unsigned uMemPageStart;
	unsigned pagesize = sysconf(_SC_PAGESIZE);

	uMemPageStart = (unsigned)uMemAddr & (~(pagesize - 1));

	nMemPageNum = (((int)uMemAddr - uMemPageStart) + nMemSize) / pagesize;

	if ((((int)uMemAddr - uMemPageStart) + nMemSize) % pagesize != 0)
	{
		nMemPageNum++;
	}

	LOGE("[MPROTECT] code start:%x, num:%d, prot:%x\n"
			, (unsigned)uMemPageStart, nMemPageNum, (unsigned)uProt);

	if (mprotect((void *)uMemPageStart, pagesize * nMemPageNum, uProt) < 0)
	{
		LOGE("[MPROTECT] ERR!!!change code previlege failed:%s\n", strerror(errno));
		return -1;
	}

	return 0;
}

void get_strftime(char *time_buffer, int size)
{
	time_t now;
	struct tm *tm_now;

	if (time_buffer == NULL || size <= 0)
		return;

	memset(time_buffer, 0, size);

	time(&now);
	tm_now = localtime(&now);

	snprintf(time_buffer, size, "%d-%d-%d %d:%d:%d"
			, 1900 + tm_now->tm_year, 1 + tm_now->tm_mon, tm_now->tm_mday
			, tm_now->tm_hour, tm_now->tm_min, tm_now->tm_sec);
}

char *trimwhitespace(char *str)
{
  char *end;

  // Trim leading space
  while(isspace(*str)) str++;

  if(*str == 0)  // All spaces?
    return str;

  // Trim trailing space
  end = str + strlen(str) - 1;
  while(end > str && isspace(*end)) end--;

  // Write new null terminator
  *(end+1) = 0;

  return str;
}

unsigned get_module_base_from_func_addr(unsigned func_addr)
{
	FILE *fp;
	int i;
	char map_path[256];
	char prot_buff[6] = "none";
	char file_line_buffer[1024];
	char *map_item, *map_item_backup;
	char *addr_start;
	unsigned long new_module_start_addr = 0;
	unsigned long same_module_start_addr = 0;

	snprintf(map_path, 256, "/proc/%d/maps", getpid());

	fp = fopen(map_path, "r");
	if (fp == NULL)
	{
		LOGE("can't open %s, err:%s\n", map_path, strerror(errno));
		return -1;
	}

	while (fgets(file_line_buffer, sizeof(file_line_buffer), fp) != NULL)
	{
		addr_start = NULL;

		map_item = strtok_r(file_line_buffer, " \t", &map_item_backup);

		addr_start = map_item;

		map_item = strtok_r(NULL, " \t", &map_item_backup);
		//printf("prot:%s\n", map_item);

		i = 0;
		while (*(addr_start + i) != '-')
			i++;
		*(addr_start + i) = 0;

		new_module_start_addr = strtoul(addr_start, NULL, 16);

		if (new_module_start_addr > func_addr)
		{
			break;
		}

		if (strcmp(map_item, "r-xp") == 0 && strstr(prot_buff, "x") == NULL)
		{
			same_module_start_addr = new_module_start_addr;
		}

		strncpy(prot_buff, map_item, 6);
	}

	fclose(fp);

	return same_module_start_addr;
}

int is_addr_valid(unsigned addr)
{
	int valid;
	int nullfd;

	if ((addr & 0x80000000) == 0x80000000)
			return 0;

	if ((addr & 0x3) > 0)
		return 0;

	valid = 1;
	nullfd = open("/dev/random", O_WRONLY);

	if (write(nullfd, (unsigned *)addr, 4) < 0)
	{
		valid = 0;
	}

	close(nullfd);

	return valid;
}

int is_addr_valid2(unsigned addr)
{
	if ((addr & 0x80000000) == 0x80000000)
		return 0;

	if ((addr & 0x3) > 0)
		return 0;

	if (addr < 0x40000000)
		return 0;

	return 1;
}

int branch_offset_extension(int offset)
{
	int value = (0xffffff & offset);
	int mask = 0x800000;
	if (mask & offset)
	{
		value += 0xFF000000;
	}

	return value;
}

#ifdef __cplusplus
}
#endif
