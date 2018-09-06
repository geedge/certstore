

#  standard component Makefile header
sp              :=  $(sp).x
dirstack_$(sp)  :=  $(d)
d               :=  $(dir)

#  component specification

OBJS_$(d) :=\
			$(OBJ_DIR)/arraylist.o\
			$(OBJ_DIR)/debug.o\
			$(OBJ_DIR)/json_c_version.o\
			$(OBJ_DIR)/json_object.o\
			$(OBJ_DIR)/json_object_iterator.o\
			$(OBJ_DIR)/json_tokener.o\
			$(OBJ_DIR)/json_util.o\
			$(OBJ_DIR)/libjson.o\
			$(OBJ_DIR)/linkhash.o\
			$(OBJ_DIR)/parse_flags.o\
			$(OBJ_DIR)/printbuf.o\
			$(OBJ_DIR)/json_checker.o\
            $(OBJ_DIR)/random_seed.o
		

CFLAGS_LOCAL += -I$(d)
$(OBJS_$(d)):  CFLAGS_LOCAL := -std=gnu99 -g -O3\
								-I$(d)


#  standard component Makefile rules

DEPS_$(d)   :=  $(OBJS_$(d):.o=.d)

CLEAN_LIST  :=  $(CLEAN_LIST) $(OBJS_$(d)) $(DEPS_$(d))

$(OBJ_DIR)/%.o:	$(d)/%.c
	$(COMPILE)

-include $(DEPS_$(d))

#  standard component Makefile footer

d   := $(dirstack_$(sp))
sp  := $(basename $(sp))
