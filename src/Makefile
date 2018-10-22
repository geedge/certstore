
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

LDFLAGS_GLOBAL += -L ./lib -lapps -lcrypto -lssl -levent -lhiredis 
LDFLAGS_GLOBAL += -L ./lib -lMESA_htable -lMESA_field_stat2 -lMESA_handle_logger -lMESA_prof_load
LDFLAGS_GLOBAL += \
                  -lpthread -lcrypt -lm -lz -ldl -lmaatframe -lstdc++ 

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

CLEAN_LIST  :=  $(CLEAN_LIST) $(OBJS) $(DEPS) $(TARGET_LIB) $(OBJ_DIR)

$(OBJ_DIR)/%.o: $(d)/%.c
	$(COMPILE)

include $(CERT_ROOT)/make/application.mk

tarball: cert_store
	if [ ! -d "package/certstroe_run/bin" ]; then mkdir -p "package/certstore_run/bin/"; fi
	if [ ! -d "package/certstroe_run/conf" ]; then mkdir -p "package/certstore_run/conf"; fi
	if [ ! -d "package/certstroe_run/cert" ]; then mkdir -p "package/certstore_run/cert"; fi
	if [ ! -d "package/certstroe_run/rule" ]; then mkdir -p "package/certstore_run/rule"; fi
	cp cert_store package/certstore_run/bin/certstore1.0
	cp ../conf/cert_store.ini package/certstore_run/conf/
	cp ../conf/pxy_obj_keyring.json package/certstore_run/conf
	cp ../conf/table_info.conf package/certstore_run/conf
#	cp ../ca/mesalab-def-cert.cer package/certstore_run/cert
#	cp ../ca/mesalab-def-cert.key package/certstore_run/cert
	cp ../ca/* package/certstore_run/cert
	cp package/Makefile package/certstore_run/
	cp ../rule/* -rf package/certstore_run/rule/
	cp package/run.sh package/certstore_run/
	cd package && tar cpfz certstore_run.tar.gz certstore_run 
	cd ..
	mv package/certstore_run.tar.gz ../release/
	rm -rf package/certstore_run
clean: 
	rm -rf $(CLEAN_LIST)
	rm -f $(TARGET)
	rm -rf package/bin package/lib package/etc

clobber: clean
	rm -rf $(OBJ_DIR)

