################################################################
# Makefile
#
# Copyright 2016 hbwoo
#
#  This file is part of TrustNETCASCstk

#compile option
export ARC =
export OPT = -Os -fPIC -fvisibility=hidden -ffunction-sections -fdata-sections
export LD = ld

TARGET_TrustNETCASCstk = libTrustNETCASCstk.so

OBJ_TrustNETCASCstk = TrustNETCASCstk/built-in.o

SUBDIRS = wolfssl-3.9.8/src \
			wolfssl-3.9.8/wolfcrypt/src \
			TrustNETCASCstk \
			testCASCstk

OBJS = wolfssl-3.9.8/src/built-in.o \
			wolfssl-3.9.8/wolfcrypt/src/built-in.o
			
STATIC_LIBS = -libwolfssl\
			-libwolfcrypt
			
STATIC_LIB_DIRS = -L./wolfssl-3.9.8/src\
	-L./wolfssl-3.9.8/wolfcrypt/src
	

all : compile $(OBJS) $(OBJ_TrustNETCASCstk)
	$(CC) $(OPT) -shared -W1,-soname,$(TARGET_TrustNETCASCstk) -o $(TARGET_TrustNETCASCstk) $(OBJS) $(OBJ_TrustNETCASCstk) -Wl,--gc-sections,-s -lpthread -lm
	$(CC) $(OPT) -ldl -o test testCASCstk/built-in.o -L./ -lTrustNETCASClient -lTrustNETCASCstk
	
compile :
	@for dir in $(SUBDIRS); do \
	make -C $$dir || exit $?; \
	done

clean :
	@for dir in $(SUBDIRS); do \
	make -C $$dir clean; \
	done
	rm -rf *.o *.i *.s $(TARGET)
