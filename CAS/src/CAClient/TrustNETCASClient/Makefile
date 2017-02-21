################################################################
# Makefile
#
# Copyright 2016 hbwoo
#
#  This file is part of TrustNETCASClient

#compile option
export ARC =
export OPT = -Os -fPIC -fvisibility=hidden -ffunction-sections -fdata-sections
export LD = ld

TARGET_TrustNETCASClient = libTrustNETCASClient.so

OBJ_TrustNETCASClient = TrustNETCASClient/built-in.o

SUBDIRS = libexpat \
			wolfssl-3.9.8/src \
			wolfssl-3.9.8/wolfcrypt/src \
			TrustNETCASClient \
			testCASClient

OBJS = libexpat/built-in.o \
			wolfssl-3.9.8/src/built-in.o \
			wolfssl-3.9.8/wolfcrypt/src/built-in.o
			
STATIC_LIBS = -libexpat\
			-libwolfssl\
			-libwolfcrypt
			
STATIC_LIB_DIRS = -L./libexpat\
	-L./wolfssl-3.9.8/src\
	-L./wolfssl-3.9.8/wolfcrypt/src
	

all : compile $(OBJS) $(OBJ_TrustNETCASClient)
	$(CC) $(OPT) -shared -W1,-soname,$(TARGET_TrustNETCASClient) -o $(TARGET_TrustNETCASClient) $(OBJS) $(OBJ_TrustNETCASClient) -Wl,--gc-sections,-s -lpthread -lm
	$(CC) $(OPT) -ldl -o test testCASClient/built-in.o -L./ -lTrustNETCASClient
	
compile :
	@for dir in $(SUBDIRS); do \
	make -C $$dir || exit $?; \
	done

clean :
	@for dir in $(SUBDIRS); do \
	make -C $$dir clean; \
	done
	rm -rf *.o *.i *.s $(TARGET)
