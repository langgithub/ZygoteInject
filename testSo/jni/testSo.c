#include <stdio.h>
#include <stdlib.h>
#include <Android/Log.h>
#include <dlfcn.h>
#include <unistd.h>
#include <dirent.h>

#define LOG_TAG "debug"
#define LOGI(fmt, args...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, fmt, ##args)
#define LOGD(fmt, args...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, fmt, ##args)
#define LOGE(fmt, args...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, fmt, ##args)

#define DEBUG_PRINT(format,args...) \
		LOGD(format, ##args)


__attribute__ ((visibility ("default"))) void log(char* mod)
{
	int pid=getpid();
	DEBUG_PRINT("Where am I?__from pid:%d",pid);
}

