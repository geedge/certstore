

#  standard component Makefile header
sp              :=  $(sp).x
dirstack_$(sp)  :=  $(d)
d               :=  $(dir)

#  component specification

OBJS_$(d) :=\
            $(OBJ_DIR)/rt_file.o\
            $(OBJ_DIR)/rt_stdlib.o\
            $(OBJ_DIR)/rt_string.o\
            $(OBJ_DIR)/rt_tmr.o\
            $(OBJ_DIR)/rt_time.o	

CFLAGS_LOCAL += -I$(d)
$(OBJS_$(d)):  CFLAGS_LOCAL := -std=gnu99 -W -Wall -Wunused-parameter -g -O3 \
                                -I$(d)\


#  standard component Makefile rules

DEPS_$(d)   :=  $(OBJS_$(d):.o=.d)

#LIBS_LIST   :=  $(LIBS_LIST) $(LIBRARY)
LIBS_LIST   :=  $(LIBS_LIST)

CLEAN_LIST  :=  $(CLEAN_LIST) $(OBJS_$(d)) $(DEPS_$(d))

-include $(DEPS_$(d))

#$(LIBRARY): $(OBJS)
#    $(MYARCHIVE)

$(OBJ_DIR)/%.o:	$(d)/%.c
	$(COMPILE)

#  standard component Makefile footer

d   := $(dirstack_$(sp))
sp  := $(basename $(sp))
