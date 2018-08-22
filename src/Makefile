
ifndef CERT_ROOT
CERT_ROOT = ..
endif

MAJOR="1.0"
BUILD="1.0" 
BUILD_FINGERPRINT=$(MAJOR).$(BUILD)
BUILD_FINGERPRINT2=$(strip $(BUILD_FINGERPRINT))

# Default simulation parameters
NUM_PROCESSORS=1

#SPASR_ARCH_TARGET:=linux_64

TARGET = cert_store

all: ${TARGET}

#  standard common Makefile fragment
include $(CERT_ROOT)/make/common.mk

# 3RD library path
LIB_PATH := $(CERT_ROOT)/libs

#  application specification

dir := .
OBJS := \
		$(OBJ_DIR)/cert_store.o \
		$(OBJ_DIR)/cert_init.o \
		$(OBJ_DIR)/cert_daemon.o\
		$(OBJ_DIR)/cert_session.o\

dir := ./components/syslogd
include $(dir)/syslog.mk
OBJS += $(OBJS_$(dir))

dir := ./rt
include $(dir)/rt.mk
OBJS += $(OBJS_$(dir))

dir := ./inc
include $(dir)/inc.mk
OBJS += $(OBJS_$(dir)) 

LDFLAGS_GLOBAL += -L ./lib -lapps -lcrypto -lssl -levent -lhiredis -lMESA_htable
LDFLAGS_GLOBAL += -L ./lib -lMESA_htable -lMESA_field_stat2 -lMESA_handle_logger -lMESA_prof_load
LDFLAGS_GLOBAL += \
                  -lpthread -lcrypt -lm -lz -ldl -lstdc++

CFLAGS_LOCAL = -std=gnu99 -g -O3 -W -Wall \
               -I.\
               -I./components/syslogd\
               -I./components/libevent\
               -I./components/redis\
               -I./components/openssl\
               -I./rt \
               -I./inc \

DEPS   :=  $(objs:.o=.d)

CLEAN_LIST  :=  $(CLEAN_LIST) $(OBJS) $(DEPS) $(TARGET_LIB) $(OBJ_DIR)

$(OBJ_DIR)/%.o: $(d)/%.c
	$(COMPILE)

include $(CERT_ROOT)/make/application.mk

tarball: cert_store
	if [ ! -d "package/bin" ]; then mkdir -p "package/bin"; fi
	if [ ! -d "package/lib" ]; then mkdir -p "package/lib"; fi
	if [ ! -d "package/etc" ]; then mkdir -p "package/etc"; fi
	cp cert_store package/bin/certstore
	cp lib/*.a 	 package/lib/
	cp ../conf/cert_store.ini package/etc/
	cd package && tar cpfz cert_store-$(BUILD_FINGERPRINT2).tar.gz bin etc lib Makefile 
	cd ..
	mv package/cert_store-$(BUILD_FINGERPRINT2).tar.gz ../release/

clean: 
	rm -rf $(CLEAN_LIST)
	rm -f $(TARGET)
	rm -rf package/bin package/lib package/etc

clobber: clean
	rm -rf $(OBJ_DIR)

