

#  standard component Makefile header
sp              :=  $(sp).x
dirstack_$(sp)  :=  $(d)
d               :=  $(dir)

#  component specification

OBJS_$(d) :=\
			$(OBJ_DIR_CPP)/moodycamel_field_stat2.o\
		

CFLAGS_LOCAL += -I$(d)
$(OBJS_$(d)):  CFLAGS_LOCAL := -std=c++11 -W -Wall -g -O3\
								-I$(d)\

#  standard component Makefile rules

DEPS_$(d)   :=  $(OBJS_$(d):.o=.d)

CLEAN_LIST  :=  $(CLEAN_LIST) $(OBJS_$(d)) $(DEPS_$(d))

$(OBJ_DIR_CPP)/%.o:	$(d)/%.cpp
	$(CPPCOMPILE)

-include $(DEPS_$(d))

#  standard component Makefile footer

d   := $(dirstack_$(sp))
sp  := $(basename $(sp))
