#  target to create object directory

$(OBJ_DIR):
	mkdir $(OBJ_DIR)
	#mkdir $(OBJ_DIR_CPP)
	
#  applications object suffix rule

$(OBJ_DIR)/%.o: %.c
	$(COMPILE)

$(OBJ_DIR)/%.o: %.S
	$(ASSEMBLE)

#$(OBJ_DIR_CPP)/%.o: %.cpp
#	$(CPPCOMPILE)
	
#  application config check and rules

-include $(OBJS:.o=.d)
#-include $(OBJS_CPP:.o=.d)

application-target: $(TARGET)

#$(TARGET): $(OBJ_DIR) $(OBJS) $(LIBS_LIST) $(OBJ_DIR_CPP) $(OBJS_CPP)
#	$(CC) -o $@ $(OBJS) $(OBJS_CPP) $(LDFLAGS_PATH) $(LIBS_LIST) $(LDFLAGS_GLOBAL) 
	
$(TARGET): $(OBJ_DIR) $(OBJS) $(LIBS_LIST)
	$(CC) -o $@ $(OBJS) $(LDFLAGS_PATH) $(LIBS_LIST) $(LDFLAGS_GLOBAL) 

$(TARGET).stp: $(TARGET)
	$(STRIP) -o $(TARGET).stp $(TARGET)
