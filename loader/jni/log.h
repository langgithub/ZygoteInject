/*
 * FileName: log.h
 * Description: ��־����
 * Version: 0.1
 * History:
 */
#ifndef LOG_H_
#define LOG_H_

#include <android/log.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>

#define LOG_LEVEL_NO 	1
#define LOG_LEVEL_ERR 	2
#define LOG_LEVEL_INFO 	3

/*
enum
{
	LOG_LEVEL_NO = 1,		// ����ӡ��־
	LOG_LEVEL_ERR,			// ��ӡ�ؼ���־
	LOG_LEVEL_INFO, 		// ��ӡ��ϸ��־
};
*/

// ������־�ı�ǩ
#define LOG_DEFAULT_TAG "<native_debug>"

#ifdef LOG_TAG
	#define LOGD(...) \
		do \
		{ \
			if (logLevel >= LOG_LEVEL_INFO) \
				__android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__); \
		} while(0)

	#define LOGE(...) \
		do \
		{ \
			if (logLevel >= LOG_LEVEL_ERR) \
				__android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__); \
		} while(0)

#else
	#define LOGD(...) \
		do \
		{ \
			if (logLevel >= LOG_LEVEL_INFO) \
				__android_log_print(ANDROID_LOG_INFO, LOG_DEFAULT_TAG, __VA_ARGS__); \
		} while(0)

	#define LOGE(...) \
		do \
		{ \
			if (logLevel >= LOG_LEVEL_ERR) \
				__android_log_print(ANDROID_LOG_ERROR, LOG_DEFAULT_TAG, __VA_ARGS__); \
		} while(0)
#endif

extern int logLevel;

void logv(char *format, ...);
void loge(char *format, ...);

#endif
