LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE 	:= loader
LOCAL_SRC_FILES := loader.c shellcode.s ctools.c log.c

LOCAL_LDLIBS+= -L$(SYSROOT)/usr/lib -llog

LOCAL_CFLAGS += -pie -fPIE
LOCAL_LDFLAGS += -pie -fPIE
LOCAL_ARM_MODE := arm
include $(BUILD_EXECUTABLE)