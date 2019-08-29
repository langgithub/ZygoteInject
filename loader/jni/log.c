#include "log.h"

#define FLOG_FILE_PATH "/sdcard/mdebugger.txt"

#ifdef __cplusplus
extern "C"
{
#endif

int logLevel = LOG_LEVEL_ERR;

void logv(char *format, ...)
{
	va_list argp;

	va_start(argp, format);

	do
	{
		if (logLevel >= LOG_LEVEL_INFO)
		{
			FILE *fp;

			fp = fopen(FLOG_FILE_PATH, "w");
			if (fp == NULL)
			{
				LOGE("can't logv %s:%s\n", FLOG_FILE_PATH, strerror(errno));
				break;
			}

			vfprintf(fp, format, argp);

			fclose(fp);
		}
	} while (0);

	va_end(argp);
}

void loge(char *format, ...)
{
	va_list argp;

	va_start(argp, format);

	do
	{
		if (logLevel >= LOG_LEVEL_ERR)
		{
			FILE *fp;

			fp = fopen(FLOG_FILE_PATH, "w");
			if (fp == NULL)
			{
				LOGE("can't logv %s:%s\n", FLOG_FILE_PATH, strerror(errno));
				break;
			}

			vfprintf(fp, format, argp);

			fclose(fp);
		}
	} while (0);

	va_end(argp);
}

#ifdef __cplusplus
}
#endif
