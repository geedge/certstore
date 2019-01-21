
ifndef CERT_ROOT
CERT_ROOT = ..
endif

MAJOR="1.0"
BUILD=$(shell git log | grep -cE 'Author:.*<.*@.*>')
BUILDSHA=$(shell git rev-parse --short HEAD)
BUILD_FINGERPRINT=$(MAJOR).$(BUILD).$(BUILDSHA)

VERSION_TARGET:=$(BUILDSHA)
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
		$(OBJ_DIR)/cert_conf.o \
		$(OBJ_DIR)/cert_daemon.o\
		$(OBJ_DIR)/cert_session.o\

dir := ./components/syslogd
include $(dir)/syslog.mk
OBJS += $(OBJS_$(dir))

dir := ./components/json
include $(dir)/json.mk
OBJS += $(OBJS_$(dir))

dir := ./rt
include $(dir)/rt.mk
OBJS += $(OBJS_$(dir))

dir := ./inc
include $(dir)/inc.mk
OBJS += $(OBJS_$(dir)) 

LDFLAGS_GLOBAL += -L ./lib -lcrypto -lssl -levent -lhiredis 
LDFLAGS_GLOBAL += -L ./lib -lMESA_htable -lMESA_field_stat2 -lMESA_handle_logger -lMESA_prof_load
LDFLAGS_GLOBAL += \
                  -lpthread -lcrypt -lm -lz -ldl -luuid -lmaatframe -lstdc++ 

CFLAGS_LOCAL = -std=gnu99 -g -O3 -W -Wall \
               -I.\
               -I./components/syslogd\
               -I./components/libevent\
               -I./components/redis\
               -I./components/openssl\
			   -I./components/json\
               -I./rt \
               -I./inc \

DEPS   :=  $(objs:.o=.d)
 
CFLAGS_GLOBAL += -DVERSION_TARGET=\"$(VERSION_TARGET)\"

CLEAN_LIST  :=  $(CLEAN_LIST) $(OBJS) $(DEPS) $(TARGET_LIB) $(OBJ_DIR)

$(OBJ_DIR)/%.o: $(d)/%.c
	$(COMPILE)

include $(CERT_ROOT)/make/application.mk

tarball: cert_store
	sh script/tarball.sh $(TARGET) $(MAJOR).$(BUILD) $(BUILDSHA)
clean: 
	rm -rf $(CLEAN_LIST)
	rm -f $(TARGET)
	rm -rf package/bin package/lib package/etc

clobber: clean
	rm -rf $(OBJ_DIR)

