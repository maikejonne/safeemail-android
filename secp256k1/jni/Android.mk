LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE    := secp256k1
MY_SOURCES := $(wildcard $(LOCAL_PATH)/src/*.c)
MY_JNI_SOURCES := $(wildcard $(LOCAL_PATH)/src/java/*.c)
LOCAL_SRC_FILES += $(MY_SOURCES) 
LOCAL_SRC_FILES +=  $(MY_JNI_SOURCES) 
LOCAL_C_INCLUDES := $(LOCAL_PATH)/include/ $(LOCAL_PATH)/src $(LOCAL_PATH)/src/java

LOCAL_CFLAGS += -D__STDC_LIMIT_MACROS -D__STDC_CONSTANT_MACROS -DSECP256K1_BUILD
LOCAL_CFLAGS += -DENABLE_MODULE_RECOVERY -DENABLE_MODULE_ECDH -DUSE_ECMULT_STATIC_PRECOMPUTATION -DUSE_FIELD_INV_BUILTIN -DUSE_NUM_NONE -DUSE_SCALAR_INV_BUILTIN
LOCAL_CFLAGS += -DUSE_FIELD_10X26 -DUSE_SCALAR_8X32 -DHAVE_BUILTIN_EXPECT
# LOCAL_CFLAGS += -O3 -W -std=c89 -pedantic -Wall -Wextra -Wcast-align -Wnested-externs -Wshadow -Wstrict-prototypes -Wno-unused-function -Wno-long-long -Wno-overlength-strings
LOCAL_CFLAGS += -O3 -W -std=c99 -pedantic -Wall -Wextra -Wcast-align -Wnested-externs -Wshadow -Wstrict-prototypes -Wno-unused-function -Wno-long-long -Wno-overlength-strings

include $(BUILD_SHARED_LIBRARY)