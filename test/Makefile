INC_DIR = ..
SRC_DIR = .
OBJ_DIR = .

CFLAGS = -Wall -Wextra -Os -g -fomit-frame-pointer -pipe
DEFINES = 
INCLUDE = -I$(INC_DIR)

all : $(OBJ_DIR)/ktest

$(OBJ_DIR)/ktest.o : $(SRC_DIR)/ktest.c
	@echo  "Compiling $@ "; gcc $(CFLAGS) $(DEFINES) $(INCLUDE) -MD -MP -c -o "$@" "$<"

$(OBJ_DIR)/ktest : $(SRC_DIR)/ktest.o
	@echo  "Building $@ "; gcc -o "$@" "$<"

clean :
	@echo  "Removing objs "; 
	@rm -rf $(OBJ_DIR)/ktest
	@rm -rf $(OBJ_DIR)/*.o
	@rm -rf $(OBJ_DIR)/*.d

